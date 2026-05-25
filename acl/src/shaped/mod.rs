// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Shape-bucketed ACL classifier backed by `cascade::Lookup`.
//!
//! Replacement for the flat `Matches`-walked classifier in
//! [`crate::layers`]. Each bucket is a [`cascade::Lookup`] backend
//! indexed by a specific key type derived from a specific packet
//! shape via [`cascade::Projection`]. The classifier picks which
//! bucket to consult by attempting [`net::headers::Headers::as_view`]
//! against each shape it owns.
//!
//! See `.scratch/acl-pat-design.md` for the design discussion that
//! led here.

pub mod acl;
pub mod source;

pub use acl::{Acl, Action, V4TcpKey, V4UdpKey};
