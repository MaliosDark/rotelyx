//! Circuits at the exit relay: the table, and the seam the sealing arrives
//! through.
//!
//! # Why this crate does not open a descriptor itself
//!
//! A circuit descriptor is sealed with the same hybrid construction the message
//! layer uses, and that lives in `rotelyx-crypto`. This crate is the vendored
//! transport. A dependency from here onto the message layer would invert the
//! layering the whole design rests on: L0 must not know what L2 is, and a build
//! of the relay that links the message cryptography is a build somebody has to
//! be told cannot read messages.
//!
//! So the opening arrives as a trait. `rotelyx-relay`, which is allowed to know
//! about both, supplies it. A relay given nothing refuses every circuit, which
//! is what a relay did before circuits existed and remains the default.

use std::sync::Arc;

use rotelyx_transport_base::EndpointId;

/// What the exit relay reads out of a descriptor.
///
/// Deliberately not the crypto crate's `Hop`: this crate does not depend on
/// that crate and must not learn to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CircuitHop {
    /// Where this circuit ends.
    pub destination: EndpointId,
    /// Where the next relay is, when this hop ends at a relay rather than at a
    /// person.
    ///
    /// `None` means the destination is a client of this relay. `Some` carries
    /// the address this relay would dial, because a relay is reached by address
    /// and not by endpoint id.
    ///
    /// A string rather than a parsed URL: this crate must not decide what a
    /// relay address looks like on behalf of the layer that sealed it, and a
    /// value that arrived from the network has not earned a type yet.
    pub next_relay: Option<String>,
    /// The key the exit relay presents to the destination as the sender, and
    /// answers on for the reply.
    ///
    /// The caller sealed this, so the relay carrying the descriptor could
    /// neither read it nor choose it.
    pub return_key: EndpointId,
}

/// Opens circuit descriptors on behalf of the relay that holds the exit key.
///
/// One method, and it returns an `Option` rather than an error on purpose: a
/// descriptor that does not open, one sealed to a different relay and one whose
/// hour has passed are the same answer here. Telling them apart on the wire
/// would let somebody probe which relay a descriptor was for.
pub trait CircuitOpener: std::fmt::Debug + Send + Sync + 'static {
    /// `sealed` is the descriptor exactly as it arrived, unvalidated.
    fn open(&self, sealed: &[u8]) -> Option<CircuitHop>;
}

/// A shared opener, or none.
pub type MaybeOpener = Option<Arc<dyn CircuitOpener>>;

/// Where a circuit goes and what name it wears, held by the connection that
/// opened it.
#[derive(Debug, Clone)]
pub(super) struct Forward {
    pub(super) destination: EndpointId,
    pub(super) return_key: EndpointId,
    /// Where this circuit continues, when it does not end here.
    pub(super) next: Option<Continuation>,
}

/// What has happened so far to a circuit that continues past this relay.
#[derive(Debug, Clone)]
pub(super) enum Continuation {
    /// Asked for, and the far relay has not answered.
    ///
    /// The entry exists in this state so that a datagram arriving before the
    /// answer is refused by name rather than forwarded into a circuit that may
    /// never open.
    Opening,
    /// Open, carried by the link to `url` under the id `far`.
    ///
    /// `far` is not the id the client here uses. The two ends of a circuit name
    /// it differently on purpose: sharing one id would let two relays compare
    /// tables and find the same circuit in both.
    Open { url: String, far: u32 },
}

/// What a chained open turned into, told to the connection that asked.
#[derive(Debug)]
pub(super) enum CircuitEvent {
    Opened { circuit: u32, url: String, far: u32 },
    Refused { circuit: u32 },
}

/// How a reply finds its way back: the connection to answer on and the circuit
/// to name.
#[derive(Debug, Clone, Copy)]
pub(super) struct Return {
    pub(super) owner: EndpointId,
    pub(super) circuit: u32,
    /// Where this circuit ends, so that endpoint going away can close it.
    ///
    /// Held here and not only in the connection's forward table because the
    /// disconnect happens in the shared table, which cannot reach into another
    /// connection's actor.
    pub(super) destination: EndpointId,
}

/// Circuits one connection may hold at once.
///
/// A circuit costs the relay two map entries and a name nobody else can then
/// claim, so it is a resource and it is bounded. Sixty four is well past what a
/// person's calls need and well short of what would let one connection fill the
/// table.
pub(super) const MAX_CIRCUITS_PER_CONNECTION: usize = 64;

/// Circuits the relay may hold across every connection.
///
/// The per-connection bound alone is not a bound: enough connections multiply
/// it. This is the second half, for the reason the socket limits give.
pub(super) const MAX_CIRCUITS_TOTAL: usize = 16_384;
