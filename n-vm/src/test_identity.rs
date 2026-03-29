// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Shared test identity resolution for the `n-vm` test infrastructure.
//!
//! Both the **host → container** tier ([`container`](crate::container)) and the
//! **container → VM** tier ([`vm`](crate::vm)) need to derive the test name
//! from a function type parameter `F` via [`std::any::type_name`].  The parsing
//! logic (strip leading `&`, split on `::`, extract the test name suffix) was
//! previously duplicated — this module provides a single implementation.
//!
//! # Stability note
//!
//! [`std::any::type_name`] is explicitly documented as not stable across
//! compiler versions.  However, the `crate::module::function` format has been
//! consistent in practice and is the same mechanism the `#[in_vm]` proc macro
//! relies on.

/// Resolved identity for a test function, derived from [`std::any::type_name`].
///
/// # Examples
///
/// ```ignore
/// fn my_test_fn() {}
///
/// let id = TestIdentity::resolve::<fn()>();
/// // id.full_type_name == "my_crate::my_test_fn" (or similar)
/// // id.test_name      == "my_test_fn"
/// ```
#[derive(Debug, Clone, Copy)]
pub(crate) struct TestIdentity {
    /// The fully-qualified type name after `&`-stripping.
    ///
    /// Not currently read outside tests, but provided for future callers
    /// that may need the full path (e.g. for logging or diagnostics).
    #[allow(dead_code)]
    ///
    /// This is the raw output of `std::any::type_name::<F>()` with any
    /// leading `&` removed.  It is a `&'static str` because `type_name`
    /// returns a `&'static str`.
    pub full_type_name: &'static str,

    /// The test name portion — everything after the first `::`.
    ///
    /// For a fully-qualified type name like `"my_crate::tests::my_test"`,
    /// this would be `"tests::my_test"`.  This matches the format expected
    /// by the Rust test harness with `--exact`.
    pub test_name: &'static str,
}

impl TestIdentity {
    /// Resolves the test identity from a function type parameter.
    ///
    /// This performs two transformations on the output of
    /// [`std::any::type_name::<F>()`]:
    ///
    /// 1. **Strip leading `&`** — when `F` is a reference to a function item
    ///    (which can happen depending on how the macro captures the function),
    ///    `type_name` prefixes the output with `"&"`.
    ///
    /// 2. **Split on the first `::`** — the portion after the first `::` is
    ///    the test name as the Rust test harness expects it with `--exact`.
    ///
    /// # Panics
    ///
    /// Panics (via `unreachable!`) if `type_name::<F>()` does not contain
    /// `::`.  This would indicate a change in the compiler's `type_name`
    /// format that breaks the invariant that function item type names are
    /// always fully qualified.
    pub fn resolve<F>() -> Self {
        let full_type_name = std::any::type_name::<F>().trim_start_matches('&');
        let (_, test_name) = full_type_name.split_once("::").unwrap_or_else(|| {
            unreachable!(
                "std::any::type_name::<F>() did not contain '::': {full_type_name:?}"
            )
        });
        Self {
            full_type_name,
            test_name,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_test_function() {}

    #[test]
    fn resolve_produces_expected_test_name() {
        let id = TestIdentity::resolve::<fn()>();
        // We can't assert the exact value of type_name (it's compiler-dependent),
        // but we can verify the structural invariants.
        assert!(
            id.full_type_name.contains("::"),
            "full_type_name should contain '::': {:?}",
            id.full_type_name,
        );
        assert!(
            !id.full_type_name.starts_with('&'),
            "full_type_name should not start with '&': {:?}",
            id.full_type_name,
        );
        // test_name should be a suffix of full_type_name
        assert!(
            id.full_type_name.ends_with(id.test_name),
            "full_type_name {:?} should end with test_name {:?}",
            id.full_type_name,
            id.test_name,
        );
    }

    /// Helper that infers the concrete function item type from a value,
    /// mirroring how the `#[in_vm]` macro passes the function identifier.
    fn resolve_for<F>(_: F) -> TestIdentity {
        TestIdentity::resolve::<F>()
    }

    #[test]
    fn resolve_with_concrete_function_item() {
        // When F is a concrete function item type (not `fn()`), type_name
        // returns the fully-qualified path of the function.
        let id = resolve_for(dummy_test_function);
        assert!(
            id.test_name.ends_with("dummy_test_function"),
            "test_name should end with 'dummy_test_function': {:?}",
            id.test_name,
        );
    }
}