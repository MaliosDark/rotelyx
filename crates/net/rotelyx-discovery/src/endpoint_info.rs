//! Address data for an endpoint.
//!
//! **Rotelyx modification.** This module used to encode and decode these types
//! as DNS TXT records, so that an endpoint could publish `identity X is at
//! address Y` to a DNS zone or the Mainline DHT and strangers could look it up.
//! Every one of those conversions is deleted, along with the `_iroh` record
//! name and the parser for it.
//!
//! What remains is the address types themselves, which the transport uses for
//! its own in-process address book. They describe an address; nothing here
//! publishes one anywhere.

use std::{
    borrow::Cow,
    collections::{BTreeSet, HashSet},
    fmt,
    hash::Hash,
    net::SocketAddr,
    str::FromStr,
    sync::Arc,
};

use rotelyx_transport_base::{EndpointAddr, EndpointId, RelayUrl, TransportAddr};
use rotelyx_error::{ensure, stack_error};


/// Data about an endpoint that may be published to and resolved from discovery services.
///
/// This includes an optional [`RelayUrl`], a set of direct addresses, and the optional
/// [`UserData`], a string that can be set by applications and is not parsed or used by iroh
/// itself.
///
/// This struct does not include the endpoint's [`EndpointId`], only the data *about* a certain
/// endpoint. See [`EndpointInfo`] for a struct that contains a [`EndpointId`] with associated [`EndpointData`].
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct EndpointData {
    /// addresses where this endpoint can be reached.
    addrs: Vec<TransportAddr>,
    /// Optional user-defined [`UserData`] for this endpoint.
    user_data: Option<UserData>,
}

fn dedup<T: Eq + Hash + Clone>(items: &mut Vec<T>) -> HashSet<T> {
    // Remove all duplicate entries, but keep the array order.
    let mut seen = HashSet::new();
    items.retain(|item| seen.insert(item.clone()));
    seen
}

impl EndpointData {
    /// Creates a new [`EndpointData`] with given list of transport addresses.
    ///
    /// The address order is preserved, so it can encode priority for address lookup
    /// services, should they not fit into e.g. a single DNS packet otherwise.
    ///
    /// If the addresses contain duplicate entries, those entries are removed.
    pub fn new(mut addrs: Vec<TransportAddr>) -> Self {
        dedup(&mut addrs);
        Self {
            addrs,
            user_data: None,
        }
    }

    /// Sets the user-defined data and returns the updated endpoint info.
    ///
    /// Useful for calling on construction after [`EndpointData::new`] or [`EndpointData::from_iter`].
    ///
    /// See also [`Self::set_user_data`].
    pub fn with_user_data(mut self, user_data: UserData) -> Self {
        self.user_data = Some(user_data);
        self
    }

    /// Adds the relay URL to the end of the endpoint data, unless it already existed.
    pub fn add_relay_url(&mut self, relay_url: RelayUrl) {
        let addr = TransportAddr::Relay(relay_url);
        if !self.addrs.contains(&addr) {
            self.addrs.push(addr);
        }
    }

    /// Adds addresses in order with duplicates or already existing addresses filtered out.
    pub fn add_ip_addrs(&mut self, addresses: Vec<SocketAddr>) {
        self.add_addrs(addresses.into_iter().map(TransportAddr::Ip))
    }

    /// Adds addresses to the endpoint data in the given order, but with duplicates filtered.
    pub fn add_addrs(&mut self, addrs: impl IntoIterator<Item = TransportAddr>) {
        let mut addr_set = dedup(&mut self.addrs);
        for addr in addrs.into_iter() {
            if !addr_set.contains(&addr) {
                self.addrs.push(addr.clone());
                addr_set.insert(addr);
            }
        }
    }

    /// Sets the user-defined data.
    pub fn set_user_data(&mut self, user_data: Option<UserData>) {
        self.user_data = user_data;
    }

    /// Removes all direct addresses from the endpoint data.
    pub fn clear_ip_addrs(&mut self) {
        self.addrs
            .retain(|addr| !matches!(addr, TransportAddr::Ip(_)));
    }

    /// Removes all relay URLs from the endpoint data.
    pub fn clear_relay_urls(&mut self) {
        self.addrs
            .retain(|addr| !matches!(addr, TransportAddr::Relay(_)));
    }

    /// Returns the relay URL of the endpoint.
    pub fn relay_urls(&self) -> impl Iterator<Item = &RelayUrl> {
        self.addrs.iter().filter_map(|addr| match addr {
            TransportAddr::Relay(url) => Some(url),
            _ => None,
        })
    }

    /// Returns the optional user-defined data of the endpoint.
    pub fn user_data(&self) -> Option<&UserData> {
        self.user_data.as_ref()
    }

    /// Returns the direct addresses of the endpoint.
    pub fn ip_addrs(&self) -> impl Iterator<Item = &SocketAddr> {
        self.addrs.iter().filter_map(|addr| match addr {
            TransportAddr::Ip(addr) => Some(addr),
            _ => None,
        })
    }

    /// Returns the full list of all known addresses.
    pub fn addrs(&self) -> impl Iterator<Item = &TransportAddr> {
        self.addrs.iter()
    }

    /// Returns whether this has any addresses.
    pub fn has_addrs(&self) -> bool {
        !self.addrs.is_empty()
    }

    /// Apply the given filter to the current addresses.
    ///
    /// Returns a vec to allow re-ordering of addresses.
    pub fn filtered_addrs(&self, filter: &AddrFilter) -> Cow<'_, Vec<TransportAddr>> {
        filter.apply(&self.addrs)
    }

    /// Returns the `EndpointData` with given filter applied.
    pub fn apply_filter(&self, filter: &AddrFilter) -> Cow<'_, Self> {
        match self.filtered_addrs(filter) {
            Cow::Borrowed(_) => Cow::Borrowed(self),
            Cow::Owned(addrs) => {
                let mut data = EndpointData::new(addrs);
                data.set_user_data(self.user_data.clone());
                Cow::Owned(data)
            }
        }
    }
}

// These From instances are faster than `EndpointData::new`, as they don't require deduplication.

impl From<BTreeSet<TransportAddr>> for EndpointData {
    fn from(addrs: BTreeSet<TransportAddr>) -> Self {
        Self {
            addrs: addrs.into_iter().collect(),
            user_data: None,
        }
    }
}

impl From<BTreeSet<SocketAddr>> for EndpointData {
    fn from(addrs: BTreeSet<SocketAddr>) -> Self {
        Self {
            addrs: addrs.into_iter().map(TransportAddr::Ip).collect(),
            user_data: None,
        }
    }
}

impl FromIterator<TransportAddr> for EndpointData {
    fn from_iter<T: IntoIterator<Item = TransportAddr>>(iter: T) -> Self {
        Self::new(iter.into_iter().collect())
    }
}

/// The function type inside [`AddrFilter`].
type AddrFilterFn =
    dyn Fn(&Vec<TransportAddr>) -> Cow<'_, Vec<TransportAddr>> + Send + Sync + 'static;

/// A filter and/or reordering function applied to transport addresses,
/// typically used by AddressLookup services in iroh before publishing.
///
/// Takes the full set of transport addresses and returns them as an ordered `Vec`,
/// allowing both filtering (by omitting addresses) and reordering (by controlling
/// the output order). A `BTreeSet` cannot preserve a custom order, so the return
/// type is `Vec` to make reordering possible.
///
/// See the documentation for each address lookup implementation for details on
/// what additional filtering the implementation may perform on top.
#[derive(Clone, Default)]
pub struct AddrFilter(Option<Arc<AddrFilterFn>>);

impl std::fmt::Debug for AddrFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0.is_some() {
            f.debug_struct("AddrFilter").finish_non_exhaustive()
        } else {
            write!(f, "identity")
        }
    }
}

impl AddrFilter {
    /// Create a new [`AddrFilter`]
    pub fn new(
        f: impl Fn(&Vec<TransportAddr>) -> Cow<'_, Vec<TransportAddr>> + Send + Sync + 'static,
    ) -> Self {
        Self(Some(Arc::new(f)))
    }

    /// Constructs a filter that doesn't filter addresses and passes all through.
    pub fn unfiltered() -> Self {
        Self::new(|addrs| Cow::Borrowed(addrs))
    }

    /// Only keep relay addresses.
    pub fn relay_only() -> Self {
        Self::new(|addrs| Cow::Owned(addrs.iter().filter(|a| a.is_relay()).cloned().collect()))
    }

    /// Only keep direct IP addresses.
    pub fn ip_only() -> Self {
        Self::new(|addrs| Cow::Owned(addrs.iter().filter(|a| !a.is_relay()).cloned().collect()))
    }

    /// Apply the address filter function to a set of addresses.
    pub fn apply<'a>(&self, addrs: &'a Vec<TransportAddr>) -> Cow<'a, Vec<TransportAddr>> {
        match &self.0 {
            Some(f) => f(addrs),
            None => Cow::Borrowed(addrs),
        }
    }
}

impl From<EndpointAddr> for EndpointData {
    fn from(endpoint_addr: EndpointAddr) -> Self {
        Self {
            // No need to check for duplicates - we already know they can't have duplicates
            addrs: endpoint_addr.addrs.into_iter().collect(),
            user_data: None,
        }
    }
}

/// User-defined data that can be published and resolved through endpoint discovery.
///
/// Under the hood this is a UTF-8 string no longer than [`UserData::MAX_LENGTH`] bytes.
///
/// Iroh does not keep track of or examine the user-defined data.
///
/// `UserData` implements [`FromStr`] and [`TryFrom<String>`], so you can
/// convert `&str` and `String` into `UserData` easily.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct UserData(String);

impl UserData {
    /// The max byte length allowed for user-defined data.
    ///
    /// In DNS discovery services, the user-defined data is stored in a TXT record character string,
    /// which has a max length of 255 bytes. We need to subtract the `user-data=` prefix,
    /// which leaves 245 bytes for the actual user-defined data.
    pub const MAX_LENGTH: usize = 245;
}

/// Error returned when an input value is too long for [`UserData`].
#[allow(missing_docs)]
#[stack_error(derive, add_meta)]
#[error("max length exceeded")]
pub struct MaxLengthExceededError {}

impl TryFrom<String> for UserData {
    type Error = MaxLengthExceededError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        ensure!(value.len() <= Self::MAX_LENGTH, MaxLengthExceededError);
        Ok(Self(value))
    }
}

impl FromStr for UserData {
    type Err = MaxLengthExceededError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        ensure!(s.len() <= Self::MAX_LENGTH, MaxLengthExceededError);
        Ok(Self(s.to_string()))
    }
}

impl fmt::Display for UserData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for UserData {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Information about an endpoint that may be published to and resolved from discovery services.
///
/// This struct couples a [`EndpointId`] with its associated [`EndpointData`].
#[derive(derive_more::Debug, Clone, Eq, PartialEq)]
pub struct EndpointInfo {
    /// The [`EndpointId`] of the endpoint this is about.
    pub endpoint_id: EndpointId,
    /// The information published about the endpoint.
    pub data: EndpointData,
}

impl From<EndpointInfo> for EndpointAddr {
    fn from(value: EndpointInfo) -> Self {
        value.into_endpoint_addr()
    }
}

impl From<EndpointAddr> for EndpointInfo {
    fn from(addr: EndpointAddr) -> Self {
        Self {
            endpoint_id: addr.id,
            data: EndpointData::from(addr.addrs),
        }
    }
}

impl EndpointInfo {
    /// Creates a new [`EndpointInfo`] with an empty [`EndpointData`].
    pub fn new(endpoint_id: EndpointId) -> Self {
        Self::from_parts(endpoint_id, Default::default())
    }

    /// Creates a new [`EndpointInfo`] from its parts.
    pub fn from_parts(endpoint_id: EndpointId, data: EndpointData) -> Self {
        Self { endpoint_id, data }
    }

    /// Adds the relay URL and returns the updated endpoint info.
    pub fn with_relay_url(mut self, relay_url: RelayUrl) -> Self {
        self.data.add_relay_url(relay_url);
        self
    }

    /// Sets the IP based addresses and returns the updated endpoint info.
    pub fn with_ip_addrs(mut self, addrs: Vec<SocketAddr>) -> Self {
        self.data.add_ip_addrs(addrs);
        self
    }

    /// Sets the user-defined data and returns the updated endpoint info.
    pub fn with_user_data(mut self, user_data: Option<UserData>) -> Self {
        self.data.set_user_data(user_data);
        self
    }

    /// Converts into a [`EndpointAddr`] by cloning the needed fields.
    pub fn to_endpoint_addr(&self) -> EndpointAddr {
        EndpointAddr {
            id: self.endpoint_id,
            addrs: self.data.addrs.iter().cloned().collect(),
        }
    }

    /// Converts into a [`EndpointAddr`].
    pub fn into_endpoint_addr(self) -> EndpointAddr {
        let Self { endpoint_id, data } = self;
        EndpointAddr {
            id: endpoint_id,
            addrs: data.addrs.into_iter().collect(),
        }
    }



    /// Returns the transport addr information.
    pub fn addrs(&self) -> impl Iterator<Item = &TransportAddr> {
        self.data.addrs()
    }

    /// Returns the relay URL of the endpoint.
    pub fn relay_urls(&self) -> impl Iterator<Item = &RelayUrl> {
        self.data.relay_urls()
    }

    /// Returns user data information, if set.
    pub fn user_data(&self) -> Option<&UserData> {
        self.data.user_data()
    }

    /// Returns the direct addresses of the endpoint.
    pub fn ip_addrs(&self) -> impl Iterator<Item = &SocketAddr> {
        self.data.ip_addrs()
    }





}





#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use hickory_resolver::{
        lookup::Lookup,
        proto::{
            op::Query,
            rr::{
                Name, RData, Record, RecordType,
                rdata::{A, TXT},
            },
        },
    };
    use rotelyx_transport_base::{EndpointId, TransportAddr};
    use rotelyx_error::{Result, StdResultExt};

    use super::{EndpointData, EndpointInfo};
    use crate::dns::TxtRecordData;

    #[test]
    fn txt_attr_roundtrip() {
        let endpoint_data = EndpointData::from_iter([
            TransportAddr::Relay("https://example.com".parse().unwrap()),
            TransportAddr::Ip("127.0.0.1:1234".parse().unwrap()),
        ])
        .with_user_data("foobar".parse().unwrap());
        let endpoint_id = "vpnk377obfvzlipnsfbqba7ywkkenc4xlpmovt5tsfujoa75zqia"
            .parse()
            .unwrap();
        let expected = EndpointInfo::from_parts(endpoint_id, endpoint_data);
        let attrs = expected.to_attrs();
        let actual = super::endpoint_info_from_attrs(&attrs);
        assert_eq!(expected, actual);
    }

    #[test]
    fn signed_packet_roundtrip() {
        let secret_key =
            SecretKey::from_str("vpnk377obfvzlipnsfbqba7ywkkenc4xlpmovt5tsfujoa75zqia").unwrap();
        let endpoint_data = EndpointData::from_iter([
            TransportAddr::Relay("https://example.com".parse().unwrap()),
            TransportAddr::Ip("127.0.0.1:1234".parse().unwrap()),
        ])
        .with_user_data("foobar".parse().unwrap());
        let expected = EndpointInfo::from_parts(secret_key.public(), endpoint_data);
        assert_eq!(expected, actual);
    }

    #[test]
    fn txt_attr_roundtrip_with_custom_addr() {
        use rotelyx_transport_base::CustomAddr;

        let bt_addr = CustomAddr::from_parts(1, &[0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6]);
        let tor_addr = CustomAddr::from_parts(42, &[0xab; 32]);

        let endpoint_data = EndpointData::from_iter([
            TransportAddr::Relay("https://example.com".parse().unwrap()),
            TransportAddr::Ip("127.0.0.1:1234".parse().unwrap()),
            TransportAddr::Custom(bt_addr),
            TransportAddr::Custom(tor_addr),
        ]);
        let endpoint_id = "vpnk377obfvzlipnsfbqba7ywkkenc4xlpmovt5tsfujoa75zqia"
            .parse()
            .unwrap();
        let expected = EndpointInfo::from_parts(endpoint_id, endpoint_data);
        let attrs = expected.to_attrs();
        let actual = super::endpoint_info_from_attrs(&attrs);
        assert_eq!(expected, actual);
    }
}
