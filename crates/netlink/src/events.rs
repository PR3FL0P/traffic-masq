//! Kernel-side change notifications.
//!
//! The daemon converges the machine towards a desired state. It needs to know
//! when to look, and polling on a timer is the wrong answer: it adds latency to
//! every change the daemon makes itself, and it wakes up constantly to ask a
//! question whose answer is almost always "nothing happened".
//!
//! rtnetlink already broadcasts every link, address, route and policy-rule
//! change. Listening to it means the daemon reacts to *anyone* touching the
//! network — dhcpcd, a hotplugged adapter, a person typing `ip addr` or
//! `ip rule` — as fast as the kernel can tell it.

use anyhow::{Context, Result};
use futures_util::StreamExt;
use netlink_packet_core_rtnetlink::{NetlinkMessage, NetlinkPayload};
use netlink_packet_route::RouteNetlinkMessage;
use netlink_sys::AsyncSocket;
use rtnetlink::new_connection;
use tokio::sync::mpsc;

/// rtnetlink multicast groups, as passed to `NETLINK_ADD_MEMBERSHIP`.
///
/// These are group *numbers*, not a bitmask.
const RTNLGRP_LINK: u32 = 1;
const RTNLGRP_IPV4_IFADDR: u32 = 5;
const RTNLGRP_IPV4_ROUTE: u32 = 7;
const RTNLGRP_IPV4_RULE: u32 = 8;

/// What the kernel told us.
///
/// Deliberately not modelled in any more detail than this. A convergence pass
/// re-reads the state it cares about anyway, so the only distinction that
/// changes behaviour is "look again" versus "you may have missed something, so
/// look at everything".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelEvent {
    /// Something in the subscribed groups changed.
    Changed,
    /// The kernel dropped notifications because our receive buffer filled up,
    /// so an unknown amount of change went unseen.
    ///
    /// This is the single failure mode that would otherwise let an event-driven
    /// daemon drift from reality forever, which is why it is reported rather
    /// than folded into `Changed`: the recipient has to resynchronise fully,
    /// not just re-check what it happens to be watching.
    Overrun,
}

/// Classify one netlink message.
///
/// Split out from the socket plumbing so the interesting half is testable
/// without a netlink socket and without privileges.
fn classify(message: &NetlinkMessage<RouteNetlinkMessage>) -> Option<KernelEvent> {
    match &message.payload {
        NetlinkPayload::InnerMessage(_) => Some(KernelEvent::Changed),
        NetlinkPayload::Overrun(_) => Some(KernelEvent::Overrun),
        // Done/Noop/Error belong to request-response traffic, not to broadcasts.
        _ => None,
    }
}

/// Subscribe to link, IPv4 address, IPv4 route and IPv4 policy-rule changes.
///
/// Returns a receiver that yields one event per relevant kernel notification.
/// The connection and the forwarding task live until the receiver is dropped.
pub fn subscribe_to_kernel_changes() -> Result<mpsc::UnboundedReceiver<KernelEvent>> {
    let (mut connection, _handle, mut messages) =
        new_connection().context("failed to open rtnetlink connection for kernel notifications")?;

    // Bind before subscribing, and subscribe at all: neither rtnetlink nor
    // netlink-proto binds the socket, because for request/response traffic it
    // does not matter. It matters here — an unbound netlink socket is not in
    // the kernel's socket table, so `netlink_broadcast` never reaches it and
    // multicast delivery silently produces nothing.
    //
    // The order is load-bearing too: `netlink_bind` writes the group mask from
    // the bind address, so binding after `add_membership` would clear the
    // memberships that were just set.
    connection
        .socket_mut()
        .socket_mut()
        .bind_auto()
        .context("failed to bind the rtnetlink notification socket")?;

    for group in [
        RTNLGRP_LINK,
        RTNLGRP_IPV4_IFADDR,
        RTNLGRP_IPV4_ROUTE,
        RTNLGRP_IPV4_RULE,
    ] {
        connection
            .socket_mut()
            .socket_mut()
            .add_membership(group)
            .with_context(|| format!("failed to subscribe to rtnetlink multicast group {group}"))?;
    }

    tokio::spawn(connection);

    let (sender, receiver) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Some((message, _)) = messages.next().await {
            let Some(event) = classify(&message) else {
                continue;
            };
            if event == KernelEvent::Overrun {
                tracing::warn!(
                    "kernel change notifications were dropped; forcing a full resynchronisation"
                );
            }
            // The receiver going away means nobody is converging any more.
            if sender.send(event).is_err() {
                break;
            }
        }
    });

    Ok(receiver)
}

#[cfg(test)]
mod tests;
