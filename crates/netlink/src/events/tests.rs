use netlink_packet_core::NetlinkHeader;

use super::*;

fn message(payload: NetlinkPayload<RouteNetlinkMessage>) -> NetlinkMessage<RouteNetlinkMessage> {
    NetlinkMessage::new(NetlinkHeader::default(), payload)
}

#[test]
fn a_broadcast_change_asks_for_another_look() {
    let link = RouteNetlinkMessage::NewLink(Default::default());
    assert_eq!(
        classify(&message(NetlinkPayload::InnerMessage(link))),
        Some(KernelEvent::Changed)
    );
}

#[test]
fn an_overrun_is_reported_separately_from_an_ordinary_change() {
    assert_eq!(
        classify(&message(NetlinkPayload::Overrun(Vec::new()))),
        Some(KernelEvent::Overrun),
        "a dropped notification must not look like an ordinary change: the \
         recipient has to resynchronise fully rather than re-check one thing"
    );
}

#[test]
fn request_response_bookkeeping_is_not_a_change() {
    assert_eq!(
        classify(&message(NetlinkPayload::Done(Default::default()))),
        None
    );
    assert_eq!(classify(&message(NetlinkPayload::Noop)), None);
}
