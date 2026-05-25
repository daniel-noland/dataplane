// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Shape-bucketed ACL.
//!
//! The classifier holds one [`cascade::Lookup`] backend per supported
//! shape. Adding a new shape is a new field plus one more arm in
//! [`Acl::classify`]; nothing else changes.
//!
//! `BTreeMap` is the simplest viable [`Lookup`] backend; the trait
//! lets us swap in LPM tries or DPDK ACL contexts per-bucket later
//! without changing the classifier's structure.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use cascade::Lookup;
use net::eth::Eth;
use net::headers::Headers;
use net::ipv4::{Ipv4, UnicastIpv4Addr};
use net::tcp::{Tcp, TcpPort};
use net::udp::{Udp, UdpPort};

use super::source::{V4TcpSource, V4UdpSource};

/// IPv4/TCP 5-tuple key.
pub type V4TcpKey = (UnicastIpv4Addr, Ipv4Addr, TcpPort, TcpPort);

/// IPv4/UDP 5-tuple key.
pub type V4UdpKey = (UnicastIpv4Addr, Ipv4Addr, UdpPort, UdpPort);

/// Per-rule action. Open for extension — variants will grow as
/// real consumers need them (metering, redirect, mark, etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Allow,
    Drop,
}

/// Shape-bucketed ACL.
///
/// Per packet, [`Self::classify`] walks the buckets in declaration
/// order and returns the first hit. Bucket order is the policy
/// designer's choice; in this first slice it is "v4/tcp then v4/udp,"
/// chosen for nothing more interesting than "tcp comes first in the
/// type."  More principled priority semantics (global priority across
/// buckets, longest-prefix-match within a bucket, ...) come later.
#[derive(Default)]
pub struct Acl {
    v4_tcp: BTreeMap<V4TcpKey, Action>,
    v4_udp: BTreeMap<V4UdpKey, Action>,
}

impl Acl {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Install a rule for IPv4/TCP packets matching the exact 5-tuple.
    pub fn install_v4_tcp(&mut self, key: V4TcpKey, action: Action) {
        self.v4_tcp.insert(key, action);
    }

    /// Install a rule for IPv4/UDP packets matching the exact 5-tuple.
    pub fn install_v4_udp(&mut self, key: V4UdpKey, action: Action) {
        self.v4_udp.insert(key, action);
    }

    /// Walk shape buckets; return the first hit.
    #[must_use]
    pub fn classify(&self, headers: &Headers) -> Option<Action> {
        if let Some(view) = headers.as_view::<(&Eth, &Ipv4, &Tcp)>()
            && let Some(&action) = self.v4_tcp.classify(&V4TcpSource(view))
        {
            return Some(action);
        }
        if let Some(view) = headers.as_view::<(&Eth, &Ipv4, &Udp)>()
            && let Some(&action) = self.v4_udp.classify(&V4UdpSource(view))
        {
            return Some(action);
        }
        None
    }
}
