//! Internal utilities to support testing.
use std::{net::Ipv4Addr, sync::Arc};

use rotelyx_transport_base::RelayUrl;
use rotelyx_relay_proto::{
    RelayConfig, RelayMap, RelayQuicConfig,
    server::{
        AllowAll, CertConfig, DynAccessControl, QuicConfig, RelayConfig as RelayServerConfig,
        Server, ServerConfig, SpawnError, TlsConfig,
    },
};
use tokio::sync::oneshot;

pub use self::qlog::QlogFileGroup;

mod qlog;
#[cfg(feature = "unstable-custom-transports")]
pub mod test_transport;

/// A drop guard to clean up test infrastructure.
///
/// After dropping the test infrastructure will asynchronously shutdown and release its
/// resources.
// Nightly sees the sender as dead code currently, but we only rely on Drop of the
// sender.
#[derive(Debug)]
#[allow(dead_code)]
pub struct CleanupDropGuard(pub(crate) oneshot::Sender<()>);

/// Runs a relay server with QUIC enabled suitable for tests.
///
/// The returned `Url` is the url of the relay server in the returned [`RelayMap`].
/// When dropped, the returned [`Server`] does will stop running.
pub async fn run_relay_server() -> Result<(RelayMap, RelayUrl, Server), SpawnError> {
    run_relay_server_with(true).await
}

/// Runs a relay server.
///
/// If `quic` is set to `true`, it will make the appropriate [`QuicConfig`] from the generated tls certificates and run the quic server at a random free port.
///
///
/// The return value is similar to [`run_relay_server`].
pub async fn run_relay_server_with(quic: bool) -> Result<(RelayMap, RelayUrl, Server), SpawnError> {
    run_relay_server_with_access(quic, Arc::new(AllowAll)).await
}

/// Runs a relay server with a custom access control.
///
/// See [`run_relay_server_with`] for details on `quic`.
pub async fn run_relay_server_with_access(
    quic: bool,
    access: Arc<dyn DynAccessControl>,
) -> Result<(RelayMap, RelayUrl, Server), SpawnError> {
    let (_certs, server_config) = rotelyx_relay_proto::server::testing::self_signed_tls_certs_and_config();

    let tls = TlsConfig::new(
        (Ipv4Addr::LOCALHOST, 0),
        CertConfig::Manual { server_config },
    );

    let mut relay = RelayServerConfig::new((Ipv4Addr::LOCALHOST, 0));
    relay.tls = Some(tls);
    relay.key_cache_capacity = Some(1024);
    relay.access = access;

    let mut config = ServerConfig::default();
    config.relay = Some(relay);
    config.quic = quic.then(|| QuicConfig::new((Ipv4Addr::LOCALHOST, 0)));

    let server = Server::spawn(config).await?;
    let url: RelayUrl = format!("https://{}", server.https_addr().expect("configured"))
        .parse()
        .expect("invalid relay url");

    let quic = server
        .quic_addr()
        .map(|addr| RelayQuicConfig::new(addr.port()));
    let n: RelayMap = RelayConfig::new(url.clone(), quic).into();
    Ok((n, url, server))
}

// `dns_and_pkarr_servers` was here: a test harness that stood up a DNS server
// and a pkarr relay so endpoints could find each other by publishing their
// addresses. It referenced `rotelyx_discovery::pkarr`, which was deleted, so it
// had not compiled in a long time; this module is behind
// `cfg(any(test, feature = "test-utils"))` and this crate is not a workspace
// member, so nothing ever built it and nothing ever said so.
//
// Publishing an identity's address to somebody else's server is the one thing
// Rotelyx is designed not to do, so the harness for it is not coming back.


pub(crate) mod dns_server {
    use std::{
        future::Future,
        net::{Ipv4Addr, SocketAddr},
    };

    use hickory_resolver::proto::{op::Message, serialize::binary::BinDecodable};
    use rotelyx_future::future::Boxed as BoxFuture;
    use tokio::{net::UdpSocket, sync::oneshot};
    use tracing::{debug, error, warn};

    use super::CleanupDropGuard;

    /// Trait used by [`run_dns_server`] for answering DNS queries.
    pub(crate) trait QueryHandler: Send + Sync + 'static {
        fn resolve(
            &self,
            query: &Message,
            reply: &mut Message,
        ) -> impl Future<Output = std::io::Result<()>> + Send;
    }

    pub(crate) type QueryHandlerFunction = Box<
        dyn Fn(&Message, &mut Message) -> BoxFuture<std::io::Result<()>> + Send + Sync + 'static,
    >;

    impl QueryHandler for QueryHandlerFunction {
        fn resolve(
            &self,
            query: &Message,
            reply: &mut Message,
        ) -> impl Future<Output = std::io::Result<()>> + Send {
            (self)(query, reply)
        }
    }

    /// Run a DNS server.
    ///
    /// Must pass a [`QueryHandler`] that answers queries.
    pub(crate) async fn run_dns_server(
        resolver: impl QueryHandler,
    ) -> std::io::Result<(SocketAddr, CleanupDropGuard)> {
        let bind_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
        let socket = UdpSocket::bind(bind_addr).await?;
        let bound_addr = socket.local_addr()?;
        let s = TestDnsServer { socket, resolver };
        let (tx, mut rx) = oneshot::channel();
        tokio::task::spawn(async move {
            tokio::select! {
                _ = &mut rx => {
                    debug!("shutting down dns server");
                }
                res = s.run() => {
                    if let Err(e) = res {
                        error!("error running dns server {e:?}");
                    }
                }
            }
        });
        Ok((bound_addr, CleanupDropGuard(tx)))
    }

    struct TestDnsServer<R> {
        resolver: R,
        socket: UdpSocket,
    }

    impl<R: QueryHandler> TestDnsServer<R> {
        async fn run(self) -> std::io::Result<()> {
            let mut buf = [0; 1450];
            loop {
                let res = self.socket.recv_from(&mut buf).await;
                let (len, from) = res?;
                if let Err(err) = self.handle_datagram(from, &buf[..len]).await {
                    warn!(?err, %from, "failed to handle incoming datagram");
                }
            }
        }

        async fn handle_datagram(
            &self,
            from: SocketAddr,
            buf: &[u8],
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
            let packet = Message::from_bytes(buf)?;
            debug!(queries = ?packet.queries, %from, "received query");
            let mut reply = packet.clone().into_response();
            self.resolver.resolve(&packet, &mut reply).await?;
            debug!(?reply, %from, "send reply");
            let buf = reply.to_vec()?;
            let len = self.socket.send_to(&buf, from).await?;
            assert_eq!(len, buf.len(), "failed to send complete packet");
            Ok(())
        }
    }
}

