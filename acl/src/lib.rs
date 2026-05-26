// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![deny(
    unsafe_code,
    clippy::all,
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
#![allow(missing_docs)] // shape settling; doc once stable

//! ACL-shaped building blocks layered on the cascade primitive.
//!
//! The crate intentionally ships no concrete classifier or header-
//! shape vocabulary: composing [`cascade::Lookup`] backends with
//! per-packet [`cascade::Projection`] impls is per-consumer work.
//! What lives here is the bridge from DPDK's `rte_acl` engine onto
//! the same generic shape ([`dpdk_lookup`]).
//!
//! See `tests/projection_demo.rs` for an end-to-end example against
//! a real [`net::headers::HeadersView`].
//!
//! [`cascade::Lookup`]: cascade::Lookup
//! [`cascade::Projection`]: cascade::Projection

#[cfg(feature = "dpdk")]
pub mod dpdk_lookup;
pub mod shaped;
