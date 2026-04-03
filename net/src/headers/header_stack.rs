//! Trait-driven header stacking for test packet construction.
//!
//! This module uses trait bounds to enforce valid layer ordering at
//! compile time.
//!
//! # Design
//!
//! Each header layer participates in three traits:
//!
//! - [`Within<T>`] -- declares that `Self` can follow layer `T`, and adjusts
//!   structural fields on the parent (e.g., setting `EthType::IPV4` on an
//!   `Eth` when `Ipv4` is stacked on top).
//! - [`Install<T>`] -- implemented on [`Headers`] for each header type,
//!   describing where to store the layer.
//! - [`Blank`] -- produces the cheapest valid instance of a header type.
//!   Unlike `Default`, `Blank` makes no semantic claims about field values.
//!
//! [`HeaderStack<T>`] is the state carrier that provides the chaining API.
//!
//! # Examples
//!
//! ```ignore
//! use net::headers::header_stack::*;
//!
//! let headers = HeaderStack::new()
//!     .eth(|e| {
//!         e.set_source(my_src_mac);
//!         e.set_destination(my_dst_mac);
//!     })
//!     .ipv4(|ip| {
//!         ip.set_source(my_src_ip);
//!         ip.set_destination(my_dst_ip);
//!     })
//!     .tcp(|tcp| {
//!         tcp.set_source(TcpPort::new_checked(12345).unwrap());
//!         tcp.set_destination(TcpPort::new_checked(80).unwrap());
//!     })
//!     .fixup(&[])
//!     .unwrap();
//! ```
//!
//! # `payload` vs `headers`
//!
//! - [`.payload(bytes)`](HeaderStack::payload) -- computes length fields *and*
//!   checksums.  Use when you need a wire-correct packet.
//! - [`.headers()`](HeaderStack::headers) -- computes length fields only.
//!   Use when checksums are irrelevant (e.g., ACL matching tests).
//!
use std::num::NonZero;

use etherparse::{IcmpEchoHeader, Icmpv4Type, Icmpv6Type};

use crate::checksum::Checksum;
use crate::eth::Eth;
use crate::eth::ethtype::EthType;
use crate::eth::mac::{DestinationMac, Mac, SourceMac};
use crate::headers::{EmbeddedHeadersBuilder, EmbeddedTransport, Headers};
use crate::icmp4::Icmp4;
use crate::icmp4::TruncatedIcmp4;
use crate::icmp6::Icmp6;
use crate::icmp6::TruncatedIcmp6;
use crate::ip::NextHeader;
use crate::ipv4::Ipv4;
use crate::ipv6::Ipv6;
use crate::parse::DeParse;
use crate::tcp::port::TcpPort;
use crate::tcp::{Tcp, TruncatedTcp};
use crate::udp::port::UdpPort;
use crate::udp::{Udp, UdpChecksum, UdpEncap};
use crate::vlan::{Pcp, Vid, Vlan};
use crate::vxlan::{Vni, Vxlan};

use super::{Net, Transport};

// Error type

/// Errors that can occur when building headers via the header stack.
#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    /// Embedded (ICMP-error) headers present but transport is not ICMP.
    #[error("embedded headers require an ICMP transport layer")]
    EmbeddedWithoutIcmp,

    /// Both embedded headers and VXLAN encapsulation were set.
    #[error("cannot have both embedded headers and VXLAN encapsulation")]
    EmbeddedAndVxlanConflict,

    /// The embedded headers have no network layer, which would produce a
    /// zero-sized `EmbeddedHeaders` (illegal).
    #[error("embedded headers must contain at least a network layer")]
    EmbeddedMissingNet,

    /// The computed IP payload length or UDP datagram length overflows `u16`.
    #[error("payload too large for IP/UDP length fields")]
    PayloadTooLarge,

    /// An IPv4 payload-length error propagated from [`Ipv4::set_payload_len`].
    #[error("IPv4 payload length overflow")]
    Ipv4PayloadOverflow,

    /// Too many VLAN tags were pushed (exceeds the parser limit).
    #[error("too many VLAN tags (max {max})", max = super::MAX_VLANS)]
    TooManyVlans,
}

// EmbeddedAssembler -- sub-builder for ICMP error embedded headers

/// Sub-builder for the headers embedded inside an ICMP error message.
///
/// Embedded headers start at the IP layer (no Ethernet / VLAN).  The
/// assembler automatically sets:
/// * The inner IP's `NextHeader` to match the chosen transport
/// * The inner IP's payload length to equal the transport header size
///   (representing a minimal "original" packet with no application data)
#[must_use]
pub struct EmbeddedAssembler {
    net: Option<Net>,
    transport: Option<EmbeddedTransport>,
}

impl EmbeddedAssembler {
    /// Create a new, empty embedded assembler.
    pub(crate) fn new() -> Self {
        Self {
            net: None,
            transport: None,
        }
    }

    /// Set the inner network layer to `Ipv4`.
    pub fn ipv4(mut self, f: impl FnOnce(&mut Ipv4)) -> Self {
        let mut ipv4 = Ipv4::default();
        f(&mut ipv4);
        self.net = Some(Net::Ipv4(ipv4));
        self
    }

    /// Set the inner network layer to `Ipv6`.
    pub fn ipv6(mut self, f: impl FnOnce(&mut Ipv6)) -> Self {
        let mut ipv6 = Ipv6::default();
        f(&mut ipv6);
        self.net = Some(Net::Ipv6(ipv6));
        self
    }

    /// Set the inner transport to `Tcp`.
    pub fn tcp(mut self, src: TcpPort, dst: TcpPort, f: impl FnOnce(&mut Tcp)) -> Self {
        set_net_next_header(&mut self.net, NextHeader::TCP);
        let mut tcp = Tcp::new(src, dst);
        f(&mut tcp);
        self.transport = Some(EmbeddedTransport::Tcp(TruncatedTcp::FullHeader(tcp)));
        self
    }

    /// Set the inner transport to `Udp`.
    pub fn udp(mut self, src: UdpPort, dst: UdpPort, f: impl FnOnce(&mut Udp)) -> Self {
        set_net_next_header(&mut self.net, NextHeader::UDP);
        let mut udp = Udp::new(src, dst);
        f(&mut udp);
        self.transport = Some(EmbeddedTransport::Udp(
            crate::udp::TruncatedUdp::FullHeader(udp),
        ));
        self
    }

    /// Set the inner transport to `Icmp4`.
    pub fn icmp4(mut self, icmp: Icmp4) -> Self {
        set_net_next_header(&mut self.net, NextHeader::ICMP);
        self.transport = Some(EmbeddedTransport::Icmp4(TruncatedIcmp4::FullHeader(icmp)));
        self
    }

    /// Set the inner transport to `Icmp6`.
    pub fn icmp6(mut self, icmp: Icmp6) -> Self {
        set_net_next_header(&mut self.net, NextHeader::ICMP6);
        self.transport = Some(EmbeddedTransport::Icmp6(TruncatedIcmp6::FullHeader(icmp)));
        self
    }

    /// Consume the assembler and produce an [`EmbeddedHeaders`] value.
    pub(crate) fn finish(mut self) -> super::EmbeddedHeaders {
        let transport_size = self.transport.as_ref().map_or(0u16, |t| t.size().get());

        match &mut self.net {
            Some(Net::Ipv4(ip)) => {
                let _ = ip.set_payload_len(transport_size);
                ip.update_checksum(&()).unwrap_or_else(|()| unreachable!());
            }
            Some(Net::Ipv6(ip)) => {
                ip.set_payload_length(transport_size);
            }
            None => {}
        }

        let mut builder = EmbeddedHeadersBuilder::default();
        builder.net(self.net);
        builder.transport(self.transport);
        #[allow(clippy::unwrap_used)]
        builder.build().unwrap()
    }
}

/// Set `NextHeader` on whichever IP variant is present.
fn set_net_next_header(net: &mut Option<Net>, nh: NextHeader) {
    match net {
        Some(Net::Ipv4(ip)) => {
            ip.set_next_header(nh);
        }
        Some(Net::Ipv6(ip)) => {
            ip.set_next_header(nh);
        }
        None => {}
    }
}

/// Declares that `Self` is a valid child of layer `T`.
///
/// When `Self` is stacked on a parent `T`, [`conform`](Within::conform)
/// adjusts structural fields on the parent to be consistent with the child.
/// For example, `Within<Eth> for Ipv4` sets `EthType::IPV4` on the Ethernet
/// header.
///
/// Conformance is called automatically by [`HeaderStack::stack`] before the parent
/// is installed into [`Headers`].
pub trait Within<T> {
    fn conform(parent: &mut T);
}

/// Declares that [`Headers`] can absorb a value of type `T`.
///
/// Each impl stores the value in the appropriate slot on `Headers`
/// (e.g., `set_eth`, `set_transport`, `vlan.try_push`, etc.).
pub trait Install<T> {
    fn install(&mut self, value: T);
}

/// Produce an arbitrary valid instance of a header type.
///
/// Unlike `Default`, `Blank` makes no claim about the *meaning* of the
/// field values -- they are simply the cheapest legal construction.
/// Callers are expected to overwrite any fields they care about via the
/// closure passed to [`HeaderStack::stack`].
pub trait Blank {
    fn blank() -> Self;
}

/// The concrete state carrier for the header-stacking builder.
///
/// `T` is the type of the layer currently being held (not yet installed
/// into [`Headers`]).  It will be installed when the next layer is stacked
/// or when [`payload`](HeaderStack::payload) / [`headers`](HeaderStack::headers) is
/// called.
///
/// Start with [`HeaderStack::new()`], chain layer methods (`.eth(...)`,
/// `.ipv4(...)`, `.tcp(...)`, etc.), then finalize with `.payload(&[])`
/// or `.headers()`.
pub struct HeaderStack<T> {
    headers: Headers,
    working: T,
}

impl HeaderStack<()> {
    /// Create a new header stack builder.
    #[must_use]
    pub fn new() -> Self {
        HeaderStack {
            headers: Headers::default(),
            working: (),
        }
    }
}

impl Default for HeaderStack<()> {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper macro to generate named layer methods on `HeaderStack<T>`.
/// Defined outside the impl block because `macro_rules!` inside impl
/// blocks is not supported.
macro_rules! layer_method {
    ($(#[$meta:meta])* $method:ident, $header:ty) => {
        $(#[$meta])*
        pub fn $method(self, f: impl FnOnce(&mut $header)) -> HeaderStack<$header>
        where
            $header: Blank + Within<T>,
            Headers: Install<$header>,
        {
            self.stack(f)
        }
    };
}

impl<T> HeaderStack<T>
where
    Headers: Install<T>,
{
    /// Push a new layer onto the stack.
    ///
    /// The new layer is created via [`Blank::blank`], then the closure `f`
    /// runs to customize it.  The *previous* top-of-stack is conformed
    /// (via [`Within`]) and installed into [`Headers`] before the new layer
    /// is created.
    pub fn stack<U>(mut self, f: impl FnOnce(&mut U)) -> HeaderStack<U>
    where
        U: Blank + Within<T>,
        Headers: Install<U>,
    {
        U::conform(&mut self.working);
        self.headers.install(self.working);

        let mut e = U::blank();
        f(&mut e);
        HeaderStack {
            headers: self.headers,
            working: e,
        }
    }

    /// Install the final layer, compute length fields, and update checksums.
    ///
    /// `payload` is the byte content following all headers on the wire.
    /// Pass `&[]` when there is no trailing payload.
    ///
    /// # Errors
    ///
    /// Returns an Err variant if the constructed packet can not be made to conform to
    /// invariants (e.g. impossible lengths).
    pub fn payload(mut self, payload: impl AsRef<[u8]>) -> Result<Headers, BuildError> {
        self.headers.install(self.working);
        validate_headers(&self.headers)?;
        fixup_lengths(&mut self.headers, payload.as_ref())?;
        self.headers.update_checksums(payload);
        Ok(self.headers)
    }

    /// Install the final layer and compute length fields only.
    ///
    /// Checksums are left as-is.  Useful when the caller does not have a
    /// real payload or does not care about checksum correctness (e.g.,
    /// testing header layout or ACL matching where only field values
    /// matter).
    ///
    /// # Errors
    ///
    /// Returns an Err variant if the constructed packet can not be made to conform to
    /// invariants (e.g. impossible lengths).
    pub fn headers(mut self) -> Result<Headers, BuildError> {
        self.headers.install(self.working);
        validate_headers(&self.headers)?;
        fixup_lengths(&mut self.headers, &[])?;
        Ok(self.headers)
    }

    layer_method!(
        /// Push an `Eth` layer.
        eth, Eth
    );
    layer_method!(
        /// Push a `Vlan` layer.
        vlan, Vlan
    );
    layer_method!(
        /// Push an `Ipv4` layer.
        ipv4, Ipv4
    );
    layer_method!(
        /// Push an `Ipv6` layer.
        ipv6, Ipv6
    );
    layer_method!(
        /// Push a `Tcp` layer.
        tcp, Tcp
    );
    layer_method!(
        /// Push a `Udp` layer.
        udp, Udp
    );
    layer_method!(
        /// Push an `Icmp4` layer.
        icmp4, Icmp4
    );
    layer_method!(
        /// Push an `Icmp6` layer.
        icmp6, Icmp6
    );
    layer_method!(
        /// Push a `Vxlan` layer.
        vxlan, Vxlan
    );
}

// Within impls -- valid layer relationships

impl Within<()> for Eth {
    fn conform(_parent: &mut ()) {}
}

impl Within<Eth> for Vlan {
    fn conform(parent: &mut Eth) {
        parent.set_ether_type(EthType::VLAN);
    }
}

impl Within<Vlan> for Vlan {
    fn conform(parent: &mut Vlan) {
        parent.set_inner_ethtype(EthType::VLAN);
    }
}

impl Within<Eth> for Ipv4 {
    fn conform(parent: &mut Eth) {
        parent.set_ether_type(EthType::IPV4);
    }
}

impl Within<Vlan> for Ipv4 {
    fn conform(parent: &mut Vlan) {
        parent.set_inner_ethtype(EthType::IPV4);
    }
}

impl Within<Eth> for Ipv6 {
    fn conform(parent: &mut Eth) {
        parent.set_ether_type(EthType::IPV6);
    }
}

impl Within<Vlan> for Ipv6 {
    fn conform(parent: &mut Vlan) {
        parent.set_inner_ethtype(EthType::IPV6);
    }
}

impl Within<Ipv4> for Tcp {
    fn conform(parent: &mut Ipv4) {
        parent.set_next_header(NextHeader::TCP);
    }
}

impl Within<Ipv6> for Tcp {
    fn conform(parent: &mut Ipv6) {
        parent.set_next_header(NextHeader::TCP);
    }
}

impl Within<Ipv4> for Udp {
    fn conform(parent: &mut Ipv4) {
        parent.set_next_header(NextHeader::UDP);
    }
}

impl Within<Ipv6> for Udp {
    fn conform(parent: &mut Ipv6) {
        parent.set_next_header(NextHeader::UDP);
    }
}

impl Within<Ipv4> for Icmp4 {
    fn conform(parent: &mut Ipv4) {
        parent.set_next_header(NextHeader::ICMP);
    }
}

impl Within<Ipv6> for Icmp6 {
    fn conform(parent: &mut Ipv6) {
        parent.set_next_header(NextHeader::ICMP6);
    }
}

impl Within<Udp> for Vxlan {
    fn conform(parent: &mut Udp) {
        let _ = parent.set_checksum(UdpChecksum::ZERO);
        parent.set_destination(Vxlan::PORT);
    }
}

// Install impls -- how Headers absorbs each layer

impl Install<()> for Headers {
    fn install(&mut self, (): ()) {}
}

impl Install<Eth> for Headers {
    fn install(&mut self, eth: Eth) {
        self.set_eth(eth);
    }
}

impl Install<Vlan> for Headers {
    fn install(&mut self, vlan: Vlan) {
        // Silently drops if at MAX_VLANS; validate_headers() checks the
        // final count and surfaces TooManyVlans.
        let _ = self.vlan.try_push(vlan);
    }
}

impl Install<Ipv4> for Headers {
    fn install(&mut self, ip: Ipv4) {
        self.net = Some(Net::Ipv4(ip));
    }
}

impl Install<Ipv6> for Headers {
    fn install(&mut self, ip: Ipv6) {
        self.net = Some(Net::Ipv6(ip));
    }
}

impl Install<Tcp> for Headers {
    fn install(&mut self, tcp: Tcp) {
        self.set_transport(Some(Transport::Tcp(tcp)));
    }
}

impl Install<Udp> for Headers {
    fn install(&mut self, udp: Udp) {
        self.set_transport(Some(Transport::Udp(udp)));
    }
}

impl Install<Icmp4> for Headers {
    fn install(&mut self, icmp: Icmp4) {
        self.set_transport(Some(Transport::Icmp4(icmp)));
    }
}

impl Install<Icmp6> for Headers {
    fn install(&mut self, icmp: Icmp6) {
        self.set_transport(Some(Transport::Icmp6(icmp)));
    }
}

impl Install<Vxlan> for Headers {
    fn install(&mut self, vxlan: Vxlan) {
        self.udp_encap = Some(UdpEncap::Vxlan(vxlan));
    }
}

impl Blank for () {
    fn blank() -> Self {}
}

impl Blank for Eth {
    fn blank() -> Self {
        // Locally-administered unicast MACs -- won't collide with real hardware.
        #[allow(clippy::unwrap_used)]
        let src = SourceMac::new(Mac([0x02, 0x00, 0x00, 0x00, 0x00, 0x01])).unwrap();
        #[allow(clippy::unwrap_used)]
        let dst = DestinationMac::new(Mac([0x02, 0x00, 0x00, 0x00, 0x00, 0x02])).unwrap();
        Eth::new(src, dst, EthType::IPV4)
    }
}

impl Blank for Vlan {
    fn blank() -> Self {
        Vlan::new(Vid::MIN, EthType::IPV4, Pcp::MIN, false)
    }
}

impl Blank for Ipv4 {
    fn blank() -> Self {
        Ipv4::default()
    }
}

impl Blank for Ipv6 {
    fn blank() -> Self {
        Ipv6::default()
    }
}

impl Blank for Tcp {
    fn blank() -> Self {
        #[allow(clippy::unwrap_used)]
        Tcp::new(
            TcpPort::new_checked(1).unwrap(),
            TcpPort::new_checked(1).unwrap(),
        )
    }
}

impl Blank for Udp {
    fn blank() -> Self {
        #[allow(clippy::unwrap_used)]
        Udp::new(
            UdpPort::new_checked(1).unwrap(),
            UdpPort::new_checked(1).unwrap(),
        )
    }
}

impl Blank for Icmp4 {
    fn blank() -> Self {
        Icmp4::with_type(Icmpv4Type::EchoRequest(IcmpEchoHeader { id: 0, seq: 0 }))
    }
}

impl Blank for Icmp6 {
    fn blank() -> Self {
        Icmp6::with_type(Icmpv6Type::EchoRequest(IcmpEchoHeader { id: 0, seq: 0 }))
    }
}

impl Blank for Vxlan {
    fn blank() -> Self {
        #[allow(clippy::unwrap_used)]
        Vxlan::new(Vni::new_checked(1).unwrap())
    }
}

// Embedded ICMP headers -- modifier on HeaderStack<Icmp4> / HeaderStack<Icmp6>
macro_rules! impl_embedded {
    ($icmp_ty:ty) => {
        impl HeaderStack<$icmp_ty> {
            /// Attach ICMP-error embedded headers.
            ///
            /// The closure receives a fresh [`EmbeddedAssembler`] and should
            /// configure the inner network and (optionally) transport headers
            /// that represent the *offending original packet*.
            #[must_use]
            pub fn embedded(
                mut self,
                f: impl FnOnce(EmbeddedAssembler) -> EmbeddedAssembler,
            ) -> Self {
                let assembler = f(EmbeddedAssembler::new());
                self.headers.embedded_ip = Some(assembler.finish());
                self
            }
        }
    };
}

impl_embedded!(Icmp4);
impl_embedded!(Icmp6);

/// Cross-layer consistency checks on fully-assembled headers.
///
/// ICMP/IP version mismatches and VXLAN-without-UDP are compile-time
/// impossible (the [`Within`] bounds prevent those combinations).  The
/// remaining checks are runtime validations for combinations that cannot
/// be ruled out structurally.
fn validate_headers(headers: &Headers) -> Result<(), BuildError> {
    if headers.embedded_ip().is_some()
        && !matches!(
            headers.transport(),
            Some(Transport::Icmp4(_) | Transport::Icmp6(_))
        )
    {
        return Err(BuildError::EmbeddedWithoutIcmp);
    }

    if headers.embedded_ip().is_some() && headers.udp_encap().is_some() {
        return Err(BuildError::EmbeddedAndVxlanConflict);
    }

    if let Some(eh) = headers.embedded_ip()
        && eh.net_headers_len() == 0
    {
        return Err(BuildError::EmbeddedMissingNet);
    }

    if headers.vlan().len() > super::MAX_VLANS {
        return Err(BuildError::TooManyVlans);
    }

    Ok(())
}

/// Compute length fields over the fully-assembled headers.
///
/// Sets:
/// 1. UDP datagram length (header + encap + payload)
/// 2. IP payload length (transport + embedded + encap + payload)
///
/// Checksums are NOT touched -- the caller decides whether to run
/// [`Headers::update_checksums`] separately.
fn fixup_lengths(headers: &mut Headers, payload: &[u8]) -> Result<(), BuildError> {
    let transport_size: u16 = headers.transport().map_or(0, |t| t.size().get());
    let embedded_size: u16 = headers.embedded_ip().map_or(0, |e| e.size().get());
    let encap_size: u16 = match headers.udp_encap() {
        Some(UdpEncap::Vxlan(v)) => v.size().get(),
        None => 0,
    };

    let payload_u16 = u16::try_from(payload.len()).map_err(|_| BuildError::PayloadTooLarge)?;

    // UDP datagram length
    if let Some(Transport::Udp(udp)) = headers.transport_mut() {
        let udp_total = Udp::MIN_LENGTH
            .get()
            .checked_add(encap_size)
            .and_then(|v| v.checked_add(payload_u16))
            .and_then(NonZero::new)
            .ok_or(BuildError::PayloadTooLarge)?;

        #[allow(unsafe_code)]
        // SAFETY: `udp_total >= Udp::MIN_LENGTH` by construction.
        unsafe {
            udp.set_length(udp_total);
        }
    }

    // IP payload length
    let ip_payload = transport_size
        .checked_add(embedded_size)
        .and_then(|v| v.checked_add(encap_size))
        .and_then(|v| v.checked_add(payload_u16))
        .ok_or(BuildError::PayloadTooLarge)?;

    match headers.net_mut() {
        Some(Net::Ipv4(ip)) => {
            ip.set_payload_len(ip_payload)
                .map_err(|_| BuildError::Ipv4PayloadOverflow)?;
        }
        Some(Net::Ipv6(ip)) => {
            ip.set_payload_length(ip_payload);
        }
        None => {}
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipv4::UnicastIpv4Addr;
    use std::net::Ipv4Addr;

    #[test]
    fn ipv4_tcp_fixup_headers() {
        let headers = HeaderStack::new()
            .eth(|_| {})
            .ipv4(|ip| {
                ip.set_source(UnicastIpv4Addr::new(Ipv4Addr::new(10, 0, 0, 1)).unwrap());
                ip.set_destination(Ipv4Addr::new(10, 0, 0, 2));
            })
            .tcp(|tcp| {
                tcp.set_source(TcpPort::new_checked(12345).unwrap());
                tcp.set_destination(TcpPort::new_checked(80).unwrap());
            })
            .headers()
            .unwrap();

        // Eth should have IPV4 ethtype (set by conform)
        assert_eq!(headers.eth().unwrap().ether_type(), EthType::IPV4);

        // IPv4 next_header should be TCP (set by conform)
        let Net::Ipv4(ipv4) = headers.net().unwrap() else {
            panic!("expected Ipv4");
        };
        assert_eq!(ipv4.next_header(), NextHeader::TCP);

        // Transport should be TCP
        assert!(matches!(headers.transport(), Some(Transport::Tcp(_))));
    }

    #[test]
    fn ipv6_udp_fixup_headers() {
        let headers = HeaderStack::new()
            .eth(|_| {})
            .ipv6(|_| {})
            .udp(|udp| {
                udp.set_source(UdpPort::new_checked(5000).unwrap());
                udp.set_destination(UdpPort::new_checked(6000).unwrap());
            })
            .headers()
            .unwrap();

        assert_eq!(headers.eth().unwrap().ether_type(), EthType::IPV6);

        let Net::Ipv6(ipv6) = headers.net().unwrap() else {
            panic!("expected Ipv6");
        };
        assert_eq!(ipv6.next_header(), NextHeader::UDP);
    }

    #[test]
    fn double_vlan_ordering() {
        let headers = HeaderStack::new()
            .eth(|_| {})
            .vlan(|v| {
                v.set_vid(Vid::new(100).unwrap());
            })
            .vlan(|v| {
                v.set_vid(Vid::new(200).unwrap());
            })
            .ipv4(|_| {})
            .tcp(|_| {})
            .headers()
            .unwrap();

        let vlans = headers.vlan();
        assert_eq!(vlans.len(), 2);
        assert_eq!(vlans[0].vid(), Vid::new(100).unwrap());
        assert_eq!(vlans[1].vid(), Vid::new(200).unwrap());
    }

    #[test]
    fn vxlan_conforms_udp() {
        let headers = HeaderStack::new()
            .eth(|_| {})
            .ipv4(|_| {})
            .udp(|udp| {
                // User sets a wrong port -- conform should overwrite it.
                udp.set_destination(UdpPort::new_checked(9999).unwrap());
            })
            .vxlan(|_| {})
            .headers()
            .unwrap();

        let Transport::Udp(udp) = headers.transport().unwrap() else {
            panic!("expected Udp");
        };
        assert_eq!(udp.destination(), Vxlan::PORT);
    }

    #[test]
    fn icmp4_with_embedded() {
        let headers = HeaderStack::new()
            .eth(|_| {})
            .ipv4(|ip| {
                ip.set_destination(Ipv4Addr::new(10, 0, 0, 1));
            })
            .icmp4(|_| {})
            .embedded(|inner| {
                inner
                    .ipv4(|ip| {
                        ip.set_source(UnicastIpv4Addr::new(Ipv4Addr::new(192, 168, 1, 1)).unwrap());
                        ip.set_destination(Ipv4Addr::new(10, 0, 0, 1));
                    })
                    .tcp(
                        TcpPort::new_checked(12345).unwrap(),
                        TcpPort::new_checked(80).unwrap(),
                        |_| {},
                    )
            })
            .payload([])
            .unwrap();

        assert!(headers.embedded_ip().is_some());
        assert!(matches!(headers.transport(), Some(Transport::Icmp4(_))));
    }

    #[test]
    fn fixup_computes_ip_payload_length() {
        let headers = HeaderStack::new()
            .eth(|_| {})
            .ipv4(|_| {})
            .tcp(|_| {})
            .payload([])
            .unwrap();

        let Net::Ipv4(ipv4) = headers.net().unwrap() else {
            panic!("expected Ipv4");
        };
        let Transport::Tcp(tcp) = headers.transport().unwrap() else {
            panic!("expected Tcp");
        };

        // IP payload length should equal the TCP header size.
        assert_eq!(ipv4.total_len(), tcp.size().get());
    }

    #[test]
    fn blank_eth_uses_locally_administered_macs() {
        let eth = Eth::blank();
        let src = eth.source();
        let dst = eth.destination();
        // Locally-administered bit (second-least-significant bit of first octet)
        assert_ne!(src.inner().0, [0; 6]);
        assert_ne!(dst.inner().0, [0; 6]);
    }

    // =====================================================================
    // Property-based tests (bolero)
    // =====================================================================

    #[cfg(feature = "bolero")]
    mod prop {
        use super::*;
        use crate::ipv4::UnicastIpv4Addr;
        use crate::ipv6::UnicastIpv6Addr;

        #[test]
        fn prop_ipv4_tcp_conform_is_correct() {
            bolero::check!().with_type().cloned().for_each(
                |(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port): (
                    SourceMac,
                    DestinationMac,
                    UnicastIpv4Addr,
                    UnicastIpv4Addr,
                    TcpPort,
                    TcpPort,
                )| {
                    let headers = HeaderStack::new()
                        .eth(|e| {
                            e.set_source(src_mac).set_destination(dst_mac);
                        })
                        .ipv4(|ip| {
                            ip.set_source(src_ip);
                            ip.set_destination(dst_ip.inner());
                        })
                        .tcp(|tcp| {
                            tcp.set_source(src_port);
                            tcp.set_destination(dst_port);
                        })
                        .payload([])
                        .unwrap();

                    assert_eq!(headers.eth().unwrap().ether_type(), EthType::IPV4);
                    let Net::Ipv4(ipv4) = headers.net().unwrap() else {
                        panic!("expected Ipv4");
                    };
                    assert_eq!(ipv4.next_header(), NextHeader::TCP);
                },
            );
        }

        #[test]
        fn prop_ipv6_udp_conform_is_correct() {
            bolero::check!().with_type().cloned().for_each(
                |(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port): (
                    SourceMac,
                    DestinationMac,
                    UnicastIpv6Addr,
                    UnicastIpv6Addr,
                    UdpPort,
                    UdpPort,
                )| {
                    let headers = HeaderStack::new()
                        .eth(|e| {
                            e.set_source(src_mac).set_destination(dst_mac);
                        })
                        .ipv6(|ip| {
                            ip.set_source(src_ip);
                            ip.set_destination(dst_ip.inner());
                        })
                        .udp(|udp| {
                            udp.set_source(src_port);
                            udp.set_destination(dst_port);
                        })
                        .payload([])
                        .unwrap();

                    assert_eq!(headers.eth().unwrap().ether_type(), EthType::IPV6);
                    let Net::Ipv6(ipv6) = headers.net().unwrap() else {
                        panic!("expected Ipv6");
                    };
                    assert_eq!(ipv6.next_header(), NextHeader::UDP);
                },
            );
        }

        #[test]
        fn prop_ipv4_tcp_payload_length_consistent() {
            bolero::check!().with_type().cloned().for_each(
                |(src_ip, dst_ip, payload): (UnicastIpv4Addr, UnicastIpv4Addr, Vec<u8>)| {
                    // Limit payload to avoid u16 overflow
                    if payload.len() > 60_000 {
                        return;
                    }

                    let headers = HeaderStack::new()
                        .eth(|_| {})
                        .ipv4(|ip| {
                            ip.set_source(src_ip);
                            ip.set_destination(dst_ip.inner());
                        })
                        .tcp(|_| {})
                        .payload(&payload)
                        .unwrap();

                    let Net::Ipv4(ipv4) = headers.net().unwrap() else {
                        panic!("expected Ipv4");
                    };
                    let Transport::Tcp(tcp) = headers.transport().unwrap() else {
                        panic!("expected Tcp");
                    };

                    let expected_payload_len = tcp.size().get() + payload.len() as u16;
                    assert_eq!(ipv4.payload_len(), expected_payload_len);
                },
            );
        }

        #[test]
        fn prop_vxlan_always_overrides_udp_dst() {
            bolero::check!()
                .with_type()
                .cloned()
                .for_each(|(user_port, vni): (UdpPort, Vni)| {
                    let headers = HeaderStack::new()
                        .eth(|_| {})
                        .ipv4(|_| {})
                        .udp(|udp| {
                            udp.set_destination(user_port);
                        })
                        .vxlan(|vx| {
                            vx.set_vni(vni);
                        })
                        .headers()
                        .unwrap();

                    let Transport::Udp(udp) = headers.transport().unwrap() else {
                        panic!("expected Udp");
                    };
                    assert_eq!(
                        udp.destination(),
                        Vxlan::PORT,
                        "VXLAN conform must override user-set UDP dst port {user_port:?} to 4789",
                    );
                });
        }
    }
}
