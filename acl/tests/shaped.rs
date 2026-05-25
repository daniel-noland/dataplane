// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Shape-bucketed ACL classifier end-to-end.

use std::net::Ipv4Addr;

use dataplane_acl::shaped::{Acl, Action};
use net::headers::Headers;
use net::headers::builder::HeaderStack;
use net::ipv4::UnicastIpv4Addr;
use net::tcp::TcpPort;
use net::udp::UdpPort;

fn unicast(addr: [u8; 4]) -> UnicastIpv4Addr {
    UnicastIpv4Addr::new(Ipv4Addr::from(addr)).unwrap()
}

fn tcp_port(port: u16) -> TcpPort {
    TcpPort::try_from(port).unwrap()
}

fn udp_port(port: u16) -> UdpPort {
    UdpPort::try_from(port).unwrap()
}

fn build_v4_tcp(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16) -> Headers {
    HeaderStack::new()
        .eth(|_| {})
        .ipv4(|ip| {
            ip.set_source(unicast(src));
            ip.set_destination(Ipv4Addr::from(dst));
        })
        .tcp(|tcp| {
            tcp.set_source(tcp_port(sport));
            tcp.set_destination(tcp_port(dport));
        })
        .build_headers()
        .unwrap()
}

fn build_v4_udp(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16) -> Headers {
    HeaderStack::new()
        .eth(|_| {})
        .ipv4(|ip| {
            ip.set_source(unicast(src));
            ip.set_destination(Ipv4Addr::from(dst));
        })
        .udp(|udp| {
            udp.set_source(udp_port(sport));
            udp.set_destination(udp_port(dport));
        })
        .build_headers()
        .unwrap()
}

#[test]
fn install_and_classify_v4_tcp() {
    let mut acl = Acl::new();
    acl.install_v4_tcp(
        (
            unicast([10, 0, 0, 1]),
            Ipv4Addr::new(10, 0, 0, 2),
            tcp_port(54321),
            tcp_port(22),
        ),
        Action::Drop,
    );

    let h = build_v4_tcp([10, 0, 0, 1], [10, 0, 0, 2], 54321, 22);
    assert_eq!(acl.classify(&h), Some(Action::Drop));
}

#[test]
fn install_and_classify_v4_udp() {
    let mut acl = Acl::new();
    acl.install_v4_udp(
        (
            unicast([10, 0, 0, 1]),
            Ipv4Addr::new(10, 0, 0, 2),
            udp_port(12345),
            udp_port(53),
        ),
        Action::Allow,
    );

    let h = build_v4_udp([10, 0, 0, 1], [10, 0, 0, 2], 12345, 53);
    assert_eq!(acl.classify(&h), Some(Action::Allow));
}

#[test]
fn miss_returns_none() {
    let acl = Acl::new();
    let h = build_v4_tcp([1, 1, 1, 1], [2, 2, 2, 2], 1234, 80);
    assert_eq!(acl.classify(&h), None);
}

#[test]
fn buckets_are_independent_by_shape() {
    // Rule installed in v4_tcp bucket; v4_udp packet with the same
    // address tuple does not hit it.
    let mut acl = Acl::new();
    acl.install_v4_tcp(
        (
            unicast([10, 0, 0, 1]),
            Ipv4Addr::new(10, 0, 0, 2),
            tcp_port(80),
            tcp_port(80),
        ),
        Action::Drop,
    );

    let h_udp = build_v4_udp([10, 0, 0, 1], [10, 0, 0, 2], 80, 80);
    assert_eq!(acl.classify(&h_udp), None);
}

#[test]
fn multiple_rules_in_same_bucket() {
    let mut acl = Acl::new();
    acl.install_v4_tcp(
        (
            unicast([10, 0, 0, 1]),
            Ipv4Addr::new(10, 0, 0, 2),
            tcp_port(1000),
            tcp_port(22),
        ),
        Action::Drop,
    );
    acl.install_v4_tcp(
        (
            unicast([10, 0, 0, 1]),
            Ipv4Addr::new(10, 0, 0, 2),
            tcp_port(1001),
            tcp_port(80),
        ),
        Action::Allow,
    );

    let drop_pkt = build_v4_tcp([10, 0, 0, 1], [10, 0, 0, 2], 1000, 22);
    let allow_pkt = build_v4_tcp([10, 0, 0, 1], [10, 0, 0, 2], 1001, 80);
    let miss_pkt = build_v4_tcp([10, 0, 0, 1], [10, 0, 0, 2], 1002, 443);

    assert_eq!(acl.classify(&drop_pkt), Some(Action::Drop));
    assert_eq!(acl.classify(&allow_pkt), Some(Action::Allow));
    assert_eq!(acl.classify(&miss_pkt), None);
}
