use std::sync::Arc;

use rotelyx_transport_base::SecretKey;
use webpki_types::CertificateDer;

#[derive(Debug)]
pub(super) struct ResolveRawPublicKeyCert {
    /// The key this endpoint was built with, and what an unrecognised caller
    /// is offered.
    key: Arc<rustls::sign::CertifiedKey>,
    /// Additional keys this endpoint will also answer as, by the id a caller
    /// names in the TLS server name.
    ///
    /// A lock rather than a plain map because keys are added while the endpoint
    /// is running: an invitation issued after startup is an address that has to
    /// start working without a restart.
    extra: std::sync::RwLock<std::collections::HashMap<rotelyx_transport_base::EndpointId, Arc<rustls::sign::CertifiedKey>>>,
}

impl ResolveRawPublicKeyCert {
    pub(super) fn new(secret_key: &SecretKey) -> Self {
        Self {
            key: Self::certified(secret_key),
            extra: Default::default(),
        }
    }

    fn certified(secret_key: &SecretKey) -> Arc<rustls::sign::CertifiedKey> {
        let private = Arc::new(IrohSecretKey::from(secret_key.clone()));
        let public = private.spki_public_key();
        let as_cert = CertificateDer::from(public.to_vec());
        Arc::new(rustls::sign::CertifiedKey::new(vec![as_cert], private))
    }

    /// Also answer as `secret_key` when a caller asks for it.
    ///
    /// # Why an endpoint would hold more than one key
    ///
    /// An endpoint that answers under one key is reachable at one address for
    /// everybody, and anything carrying that traffic learns which endpoint
    /// talks to which. Giving each contact an address of its own removes that,
    /// and an address is a key: to be reachable at several, an endpoint has to
    /// be able to prove it holds several.
    ///
    /// # How the right one is chosen
    ///
    /// The caller already says which. This transport encodes the endpoint id it
    /// is dialling into the TLS server name, so the id is in the ClientHello,
    /// before any key has to be produced. See [`super::name`].
    ///
    /// Unknown or absent, the key this endpoint was built with is offered and
    /// the caller rejects it if that is not who it wanted. That is the same
    /// outcome as before this existed.
    pub(super) fn also_answer_as(&self, secret_key: &SecretKey) {
        self.extra
            .write()
            .expect("resolver lock")
            .insert(secret_key.public(), Self::certified(secret_key));
    }

    /// The key to present for a ClientHello, by the name it asked for.
    fn for_server_name(&self, name: Option<&str>) -> Arc<rustls::sign::CertifiedKey> {
        let wanted = name.and_then(super::name::decode);
        if let Some(id) = wanted {
            if let Some(key) = self.extra.read().expect("resolver lock").get(&id) {
                return Arc::clone(key);
            }
        }
        Arc::clone(&self.key)
    }
}

impl rustls::client::ResolvesClientCert for ResolveRawPublicKeyCert {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[rustls::SignatureScheme],
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(Arc::clone(&self.key))
    }

    fn only_raw_public_keys(&self) -> bool {
        true
    }

    fn has_certs(&self) -> bool {
        true
    }
}

impl rustls::server::ResolvesServerCert for ResolveRawPublicKeyCert {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(self.for_server_name(client_hello.server_name()))
    }

    fn only_raw_public_keys(&self) -> bool {
        true
    }
}

#[derive(Debug, Clone, derive_more::From)]
struct IrohSecretKey {
    #[from]
    key: SecretKey,
}

impl IrohSecretKey {
    fn spki_public_key(&self) -> webpki_types::SubjectPublicKeyInfoDer<'static> {
        rustls::sign::public_key_to_spki(
            &webpki_types::alg_id::ED25519,
            self.key.public().as_bytes(),
        )
    }
}
impl rustls::sign::SigningKey for IrohSecretKey {
    fn choose_scheme(
        &self,
        offered: &[rustls::SignatureScheme],
    ) -> Option<Box<dyn rustls::sign::Signer>> {
        if offered.contains(&rustls::SignatureScheme::ED25519) {
            Some(Box::new(self.clone()))
        } else {
            None
        }
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        rustls::SignatureAlgorithm::ED25519
    }

    fn public_key(&self) -> Option<webpki_types::SubjectPublicKeyInfoDer<'_>> {
        Some(self.spki_public_key())
    }
}

impl rustls::sign::Signer for IrohSecretKey {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        Ok(self.key.sign(message).to_bytes().to_vec())
    }

    fn scheme(&self) -> rustls::SignatureScheme {
        rustls::SignatureScheme::ED25519
    }
}
