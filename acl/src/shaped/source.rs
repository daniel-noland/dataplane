// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Per-shape source wrappers over [`net::headers::HeadersView`].
//!
//! Each source is a thin `#[repr(transparent)]` newtype that hosts
//! one or more [`cascade::Projection`] impls. The newtype reads
//! better at use sites than a bare `&HeadersView<S>` and is the
//! natural place to grow domain-specific helpers as the shape's
//! match flavor evolves.

use std::net::Ipv4Addr;

use cascade::Projection;
use net::eth::Eth;
use net::headers::{HeadersView, Look};
use net::ipv4::{Ipv4, UnicastIpv4Addr};
use net::tcp::{Tcp, TcpPort};
use net::udp::{Udp, UdpPort};

/// IPv4/TCP packet source.
#[repr(transparent)]
pub struct V4TcpSource<'a>(pub &'a HeadersView<(&'a Eth, &'a Ipv4, &'a Tcp)>);

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

/// IPv4/UDP packet source.
#[repr(transparent)]
pub struct V4UdpSource<'a>(pub &'a HeadersView<(&'a Eth, &'a Ipv4, &'a Udp)>);

impl Projection<(UnicastIpv4Addr, Ipv4Addr, UdpPort, UdpPort)> for &V4UdpSource<'_> {
    fn project(self) -> (UnicastIpv4Addr, Ipv4Addr, UdpPort, UdpPort) {
        let (_eth, ipv4, udp) = self.0.look();
        (
            ipv4.source(),
            ipv4.destination(),
            udp.source(),
            udp.destination(),
        )
    }
}
