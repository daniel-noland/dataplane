// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Source-to-key extraction.
//!
//! See [`Projection`].

/// Extract a key of type `T` from `self`.
///
/// Implement on `&'a Source` (rather than `Source` directly) so the
/// lifetime threads naturally into `T` when `T` contains references;
/// for owned `T`, the lifetime is in scope but unused. The same
/// source can implement `Projection<T>` for many `T`, each picked at
/// the call site by type inference from a downstream
/// [`Lookup`](crate::Lookup) backend's key type.
///
/// `self` is consumed because the receiver is a reference; consuming
/// it just moves a pointer.
pub trait Projection<T> {
    fn project(self) -> T;
}
