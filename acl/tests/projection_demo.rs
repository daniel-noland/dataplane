// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! End-to-end demo: real `HeadersView` -> `Projection` -> `Lookup` ->
//! `Action`.
//!
//! Validates the trait mechanics from `cascade::projection` /
//! `cascade::lookup` against real packet headers (rather than the
//! synthetic `Pkt` struct used in cascade's own unit tests).

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use cascade::{Lookup, Projection};
use net::eth::Eth;
use net::headers::builder::HeaderStack;
use net::headers::{HeadersView, Look};
use net::ipv4::{Ipv4, UnicastIpv4Addr};
use net::tcp::{Tcp, TcpPort};

// ---------------------------------------------------------------------------
// Source type: thin newtype over `&HeadersView<(&Eth, &Ipv4, &Tcp)>`.
//
// `&HeadersView<...>` could host `Projection` impls directly, but a named
// newtype reads better at use sites ("here's where we extract lookup keys")
// and gives us a place to grow domain-specific helpers later.
// ---------------------------------------------------------------------------

#[allow(dead_code)]
#[repr(transparent)]
struct V4TcpSource<'a>(&'a HeadersView<(&'a Eth, &'a Ipv4, &'a Tcp)>);

// 5-tuple projection.
impl Projection<(UnicastIpv4Addr, Ipv4Addr, TcpPort, TcpPort)> for &V4TcpSource<'_> {
    fn project(self) -> (UnicastIpv4Addr, Ipv4Addr, TcpPort, TcpPort) {
        let (_eth, ipv4, tcp) = self.0.look();
        (
            ipv4.source(),
            ipv4.destination(),
            tcp.source(),
            tcp.destination(),
        )
    }
}

// 2-tuple projection on the same source -- demonstrates multi-impl.
impl Projection<(UnicastIpv4Addr, Ipv4Addr)> for &V4TcpSource<'_> {
    fn project(self) -> (UnicastIpv4Addr, Ipv4Addr) {
        let (_eth, ipv4, _tcp) = self.0.look();
        (ipv4.source(), ipv4.destination())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
enum Action {
    Allow,
    Drop,
}

fn build_v4_tcp() -> net::headers::Headers {
    let src = UnicastIpv4Addr::new(Ipv4Addr::new(10, 0, 0, 1)).unwrap();
    let dst = Ipv4Addr::new(10, 0, 0, 2);
    let sport = TcpPort::try_from(54321u16).unwrap();
    let dport = TcpPort::try_from(22u16).unwrap();
    HeaderStack::new()
        .eth(|_| {})
        .ipv4(|ip| {
            ip.set_source(src);
            ip.set_destination(dst);
        })
        .tcp(|tcp| {
            tcp.set_source(sport);
            tcp.set_destination(dport);
        })
        .build_headers()
        .unwrap()
}

#[test]
fn five_tuple_lookup_against_real_packet() {
    let h = build_v4_tcp();
    let view = h
        .as_view::<(&Eth, &Ipv4, &Tcp)>()
        .expect("packet must match shape");
    let src = V4TcpSource(view);

    // Table keyed by the 5-tuple.
    let mut table: BTreeMap<(UnicastIpv4Addr, Ipv4Addr, TcpPort, TcpPort), Action> =
        BTreeMap::new();
    table.insert(
        (
            UnicastIpv4Addr::new(Ipv4Addr::new(10, 0, 0, 1)).unwrap(),
            Ipv4Addr::new(10, 0, 0, 2),
            TcpPort::try_from(54321u16).unwrap(),
            TcpPort::try_from(22u16).unwrap(),
        ),
        Action::Drop,
    );

    assert_eq!(table.classify(&src), Some(&Action::Drop));
}

#[test]
fn two_tuple_lookup_against_same_real_packet() {
    let h = build_v4_tcp();
    let view = h.as_view::<(&Eth, &Ipv4, &Tcp)>().unwrap();
    let src = V4TcpSource(view);

    // Same source; different K; the 2-tuple `Projection` impl is selected
    // by inference from the table's key type.
    let mut table: BTreeMap<(UnicastIpv4Addr, Ipv4Addr), Action> = BTreeMap::new();
    table.insert(
        (
            UnicastIpv4Addr::new(Ipv4Addr::new(10, 0, 0, 1)).unwrap(),
            Ipv4Addr::new(10, 0, 0, 2),
        ),
        Action::Allow,
    );

    assert_eq!(table.classify(&src), Some(&Action::Allow));
}

#[test]
fn wrong_packet_shape_means_no_source_at_all() {
    // UDP packet doesn't match (&Eth, &Ipv4, &Tcp) -> no V4TcpSource to
    // build, no lookup to attempt.  This is the type-level guarantee:
    // the classifier code path is never even reached on a shape miss.
    let h = HeaderStack::new()
        .eth(|_| {})
        .ipv4(|_| {})
        .udp(|_| {})
        .build_headers()
        .unwrap();
    assert!(h.as_view::<(&Eth, &Ipv4, &Tcp)>().is_none());
}

#[test]
fn miss_in_table_returns_none() {
    let h = build_v4_tcp();
    let view = h.as_view::<(&Eth, &Ipv4, &Tcp)>().unwrap();
    let src = V4TcpSource(view);

    let table: BTreeMap<(UnicastIpv4Addr, Ipv4Addr, TcpPort, TcpPort), Action> = BTreeMap::new();
    assert_eq!(table.classify(&src), None);
}
