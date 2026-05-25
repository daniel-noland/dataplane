// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

// The `Lookup::lookup` body calls `AclContext::classify`, which is
// `unsafe` because DPDK reads at least `min_input_size` bytes from
// each buffer without bounds checks.  The `STRIDE` const generic is
// the safety witness: `Self::new` rejects construction unless
// `STRIDE >= min_input_size`, so a `&[u8; STRIDE]` argument is
// statically wide enough.  See the per-call SAFETY block for the
// pointer-validity argument.
#![allow(unsafe_code)]

//! [`cascade::Lookup`] backend over a DPDK [`AclContext`].
//!
//! Wraps a built [`dpdk::acl::AclContext`] so it can be slotted into
//! the same generic classifier shapes that drive a `BTreeMap`-backed
//! `Lookup` in tests.  Per-packet classification calls
//! `rte_acl_classify` with a one-element batch; the SIMD batch path
//! is the natural follow-on once we have a batch `Lookup` trait
//! (single-packet calls forfeit most of the SIMD win).
//!
//! Construction requires a live EAL because the underlying
//! [`AclContext`] is built by DPDK; the type *compiles* without an
//! EAL though, which is the load-bearing property — generic tests
//! against `Lookup<K, A>` never link DPDK because they use
//! `BTreeMap` or `HashMap` instead.

use std::fmt;

use cascade::Lookup;
use dpdk::acl::{AclContext, Built};

/// A `Lookup<[u8; STRIDE], A>` backed by a built DPDK
/// [`AclContext`].
///
/// `actions` is indexed by `user_data - 1` (DPDK's rule user-data is
/// 1-based; `0` means "no match"); pushing in the same order as the
/// rules were `add_rules`'d keeps the indexing aligned.
///
/// `STRIDE` must be at least the context's
/// [`AclBuildConfig::min_input_size`][dpdk::acl::AclBuildConfig::min_input_size];
/// [`Self::new`] checks this and rejects mismatches at construction.
/// After that, the [`Lookup`] hot path is safe because the buffer is
/// a `&[u8; STRIDE]`, statically large enough for the unchecked DPDK
/// read.
pub struct DpdkAclLookup<const N_FIELDS: usize, const STRIDE: usize, A> {
    ctx: AclContext<N_FIELDS, Built<N_FIELDS>>,
    actions: Vec<A>,
}

impl<const N_FIELDS: usize, const STRIDE: usize, A> DpdkAclLookup<N_FIELDS, STRIDE, A> {
    /// Construct.
    ///
    /// # Errors
    /// Returns [`StrideTooSmall`] if `STRIDE` is less than the
    /// context's `min_input_size()`. DPDK reads `min_input_size`
    /// bytes per buffer; if `STRIDE` is smaller we'd hand it a
    /// short buffer.
    pub fn new(
        ctx: AclContext<N_FIELDS, Built<N_FIELDS>>,
        actions: Vec<A>,
    ) -> Result<Self, StrideTooSmall> {
        let required = ctx.build_config().min_input_size();
        if STRIDE < required {
            return Err(StrideTooSmall {
                stride: STRIDE,
                required,
            });
        }
        Ok(Self { ctx, actions })
    }

    /// The underlying DPDK context.
    #[must_use]
    pub fn ctx(&self) -> &AclContext<N_FIELDS, Built<N_FIELDS>> {
        &self.ctx
    }

    /// The action table.  Index `i` holds the action for the rule
    /// whose `user_data` is `i + 1`.
    #[must_use]
    pub fn actions(&self) -> &[A] {
        &self.actions
    }
}

impl<const N_FIELDS: usize, const STRIDE: usize, A> Lookup<[u8; STRIDE], A>
    for DpdkAclLookup<N_FIELDS, STRIDE, A>
{
    fn lookup(&self, key: &[u8; STRIDE]) -> Option<&A> {
        let ptrs = [key.as_ptr()];
        let mut results = [0u32; 1];
        // SAFETY: STRIDE >= min_input_size was checked in `new`, so
        // the buffer is large enough for DPDK's unchecked read.  The
        // pointer is to a stack slot owned by the caller's borrow of
        // `key`, valid for the duration of this call.
        unsafe {
            self.ctx.classify(&ptrs, &mut results, 1).ok()?;
        }
        let user_data = results[0];
        if user_data == 0 {
            return None;
        }
        let idx = usize::try_from(user_data).ok()?.checked_sub(1)?;
        self.actions.get(idx)
    }
}

/// `STRIDE` smaller than the DPDK context's `min_input_size`.
///
/// DPDK reads `min_input_size` bytes per buffer without bounds
/// checks; a smaller `STRIDE` would be undefined behavior.
#[derive(Debug)]
pub struct StrideTooSmall {
    /// The configured `STRIDE` const generic.
    pub stride: usize,
    /// The context's reported `min_input_size`.
    pub required: usize,
}

impl fmt::Display for StrideTooSmall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DpdkAclLookup STRIDE={} is smaller than the context's min_input_size={}",
            self.stride, self.required,
        )
    }
}

impl std::error::Error for StrideTooSmall {}
