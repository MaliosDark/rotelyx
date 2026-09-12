//! A room: the one place a group call's media goes, and comes back from.
//!
//! # Why a relay runs one
//!
//! Without it, a call between more than two people did not exist. Every
//! client held one connection to one peer, so a "group call" was two members
//! of the group hearing each other and the rest hearing nothing. The
//! forwarding decision was written and tested a month before this file, and
//! nothing ran it. Every messenger with group calls that keeps them end to end
//! encrypted does what this does: each participant sends one stream to a
//! forwarder that cannot read it and receives everybody else's from the same
//! place. One had to write its forwarder from scratch after finding the ones
//! available could not pass eight participants. Ours was already here.
//!
//! # What it is
//!
//! An endpoint of this relay's own, bound with the relay's identity and
//! reachable through the relay the way any endpoint is, so a phone that only
//! ever dials through a relay dials this the same way. A participant connects,
//! sends one datagram saying which room and which seat, and from then on every
//! datagram it sends is handed to everybody else in that room and every
//! datagram anybody else sends is handed to it.
//!
//! The routing is [`rotelyx_media::forward::Forwarder`] and the reasons it can
//! route what it cannot read are written there. This file adds only what that
//! module says it deliberately does not do: the sockets, tying a connection to
//! a seat, and the rooms themselves.
//!
//! # What the relay learns
//!
//! Which seats are in which room and when each one speaks. It already saw
//! that a call was happening between these endpoints when it relayed them to
//! each other; now it sees it in one place. It does not learn who they are: an
//! endpoint on a call is a transport key made for that call, and the room id
//! is a value the group agreed that names nothing outside the group.
//!
//! # Admission
//!
//! Whoever holds the room id may join it. The id is derived from the call's
//! own binding, which every member already holds and nobody else does, and it
//! is thirty two bytes of something nobody can guess. A gatecrasher who did
//! obtain it would receive sealed frames it cannot open and could send frames
//! every recipient refuses, because a frame is authenticated under the group's
//! media key. What it could do is occupy a seat and cost bandwidth, which is
//! bounded by the seats a room has and the rooms a relay will hold. That is
//! the same bound a caller has on the relay today.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use rotelyx_media::forward::{parse_join, Forwarder, Join, Routed, ROOM_ID_LEN};
use rotelyx_net::{Connection, NetEndpoint};

/// How many rooms one relay holds at once.
///
/// A room costs a forwarder and a map of connections, which is nothing, and
/// the bandwidth of every stream in it multiplied by every listener, which is
/// everything. This bounds the second by bounding the first; a relay that
/// wants more raises it knowing what each one costs.
pub const MAX_ROOMS: usize = 256;

/// The rooms this relay is holding.
#[derive(Default)]
pub struct Rooms {
    inner: Mutex<HashMap<[u8; ROOM_ID_LEN], Room>>,
}

struct Room {
    forwarder: Forwarder,
    /// The connection behind each seat, so a routed copy can be delivered.
    legs: HashMap<u8, Connection>,
}

impl Rooms {
    /// Seat a connection in a room, creating the room if this is its first.
    fn join(&self, join: Join, conn: Connection) -> Result<()> {
        let mut rooms = self.inner.lock().expect("not poisoned");
        if !rooms.contains_key(&join.room) && rooms.len() >= MAX_ROOMS {
            anyhow::bail!("this relay is holding {MAX_ROOMS} rooms and will not hold another");
        }
        let room = rooms.entry(join.room).or_insert_with(|| Room {
            forwarder: Forwarder::new(),
            legs: HashMap::new(),
        });
        room.forwarder
            .join(join.seat)
            .map_err(|e| anyhow::anyhow!("seat {}: {e}", join.seat))?;
        room.legs.insert(join.seat, conn);
        let seats = room.legs.len();
        tracing::debug!(rooms = rooms.len(), seats, "seated");
        Ok(())
    }

    /// A participant is gone. The room goes with the last one.
    fn leave(&self, join: Join) {
        let mut rooms = self.inner.lock().expect("not poisoned");
        let Some(room) = rooms.get_mut(&join.room) else { return };
        let _ = room.forwarder.leave(join.seat);
        room.legs.remove(&join.seat);
        if room.legs.is_empty() {
            rooms.remove(&join.room);
        }
    }

    /// Where one datagram goes, and the connections to put it on.
    ///
    /// The connections are cloned out under the lock and delivered outside it,
    /// so a slow leg never holds up the room.
    fn route(&self, join: Join, datagram: &[u8]) -> Result<(Routed, Vec<Connection>)> {
        let mut rooms = self.inner.lock().expect("not poisoned");
        let room = rooms
            .get_mut(&join.room)
            .context("the room is gone")?;
        let routed = room.forwarder.route(join.seat, datagram)?;
        let legs = routed
            .to
            .iter()
            .filter_map(|seat| room.legs.get(seat).cloned())
            .collect();
        Ok((routed, legs))
    }
}

/// Accept participants for as long as the endpoint lives.
pub async fn serve(endpoint: NetEndpoint, rooms: Arc<Rooms>) -> Result<()> {
    loop {
        let (peer, conn) = endpoint
            .accept_media()
            .await
            .context("accepting a room participant")?;
        let rooms = rooms.clone();
        tokio::spawn(async move {
            if let Err(e) = participant(conn, rooms).await {
                tracing::debug!(peer = %peer, error = %e, "room participant left");
            }
        });
    }
}

/// One participant, from its join to its last datagram.
async fn participant(conn: Connection, rooms: Arc<Rooms>) -> Result<()> {
    // The first datagram is the join and nothing else is accepted until it
    // has arrived: a media frame before a seat is a frame from nobody.
    let first = conn
        .read_datagram()
        .await
        .context("waiting for the join")?;
    let join = parse_join(&first)?;
    rooms.join(join, conn.clone())?;

    let outcome = carry(&conn, join, &rooms).await;
    rooms.leave(join);
    outcome
}

/// Every datagram after the join, until the connection ends.
async fn carry(conn: &Connection, join: Join, rooms: &Rooms) -> Result<()> {
    loop {
        let datagram = match conn.read_datagram().await {
            Ok(d) => d,
            // The connection closing is how a participant leaves. Not an
            // error, and not worth a line at anybody.
            Err(_) => return Ok(()),
        };

        let (_, legs) = match rooms.route(join, &datagram) {
            Ok(routed) => routed,
            // A frame that names a different seat than the connection it
            // came in on, or arrived before the room knew this seat. Dropped,
            // for the reasons `Forwarder::route` gives, and the participant
            // stays: one bad frame is not a reason to hang up on somebody.
            Err(e) => {
                tracing::debug!(error = %e, "dropped a frame");
                continue;
            }
        };

        for leg in legs {
            // Best effort, like every datagram. A leg whose buffer is full
            // loses this frame and the codec conceals it, which is what
            // happens on any network and what the codec was built for.
            let _ = leg.send_datagram(datagram.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rotelyx_media::forward::{join_datagram, JOIN_MAGIC};

    #[test]
    fn a_join_round_trips() {
        let room = [7u8; ROOM_ID_LEN];
        let wire = join_datagram(&room, 5);
        let back = parse_join(&wire).expect("a join");
        assert_eq!(back, Join { room, seat: 5 });
    }

    #[test]
    fn a_media_frame_is_not_mistaken_for_a_join() {
        // A frame is longer than a join, and the check is on length before
        // anything else, so a frame that happened to start with the marker
        // would still be refused.
        let mut frame = join_datagram(&[1u8; ROOM_ID_LEN], 0);
        frame.extend_from_slice(&[0u8; 64]);
        assert!(parse_join(&frame).is_err());

        let short = &JOIN_MAGIC[..3];
        assert!(parse_join(short).is_err());
    }

    #[test]
    fn a_join_without_the_marker_is_refused() {
        let mut wire = join_datagram(&[2u8; ROOM_ID_LEN], 1);
        wire[0] = b'X';
        assert!(parse_join(&wire).is_err());
    }
}
