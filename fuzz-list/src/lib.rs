// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Fuzz test registration and custom harness.
//!
//! This crate provides a [`linkme::distributed_slice`]-based registry for bolero fuzz tests
//! and a custom test harness that can list and run them via `cargo-bolero`.
//!
//! # Setup
//!
//! 1. Add `fuzz-list` as an optional dependency gated on the `bolero` feature:
//!
//!    ```toml
//!    [features]
//!    bolero = ["dep:bolero", "dep:fuzz-list"]
//!
//!    [dependencies]
//!    bolero = { workspace = true, optional = true }
//!    fuzz-list = { workspace = true, optional = true }
//!    ```
//!
//! 2. Annotate bolero tests with `#[fuzz]` (inside a `cfg(any(test, feature = "bolero"))` module):
//!
//!    ```ignore
//!    #[cfg(any(test, feature = "bolero"))]
//!    mod fuzz_tests {
//!        use fuzz_list::fuzz;
//!
//!        #[fuzz]
//!        #[test]
//!        fn my_property_test() {
//!            bolero::check!().with_type().cloned().for_each(|v: MyType| {
//!                // property assertions
//!            });
//!        }
//!    }
//!    ```
//!
//! 3. Add a custom harness integration test:
//!
//!    ```toml
//!    [[test]]
//!    name = "fuzz"
//!    path = "tests/fuzz/main.rs"
//!    harness = false
//!    required-features = ["bolero"]
//!    ```
//!
//!    ```ignore
//!    // tests/fuzz/main.rs
//!    fn main() {
//!        fuzz_list::main();
//!    }
//!    ```
//!
//! # Harness usage
//!
//! ```bash
//! # List all fuzz tests in a package:
//! cargo test -p my-crate --features bolero --test fuzz -- list
//!
//! # Run a specific fuzz test:
//! cargo test -p my-crate --features bolero --test fuzz -- run <filter>
//!
//! # Run with options:
//! cargo test -p my-crate --features bolero --test fuzz -- run <filter> \
//!   --timeout 200s --sanitizer address --jobs 4
//!
//! # Build an instrumented binary (for bare-environment deployment):
//! cargo test -p my-crate --features bolero --test fuzz -- build
//! ```
//!
//! # Sanitizer defaults
//!
//! Feature flags control which sanitizers are enabled by default for all `#[fuzz]` tests:
//!
//! - `default-address` -- enable address sanitizer by default
//! - `default-thread` -- enable thread sanitizer by default
//!
//! Individual tests override defaults with the `sanitizers` argument:
//!
//! ```ignore
//! #[fuzz(sanitizers += thread)]          // add to defaults
//! #[fuzz(sanitizers -= address)]         // remove from defaults
//! #[fuzz(sanitizers = thread)]           // exact set (ignore defaults)
//! #[fuzz(sanitizers -= thread, address)] // remove multiple
//! ```

#![deny(
    unsafe_code,
    missing_docs,
    clippy::all,
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
// linkme's distributed_slice generates unsafe code in the defining crate
#![allow(unsafe_code)]

pub mod harness;

pub use fuzz_list_macros::fuzz;
pub use linkme::distributed_slice;

/// Sanitizer configuration for a fuzz test.
#[derive(Debug, Copy, Clone, serde::Serialize)]
pub struct Sanitize {
    /// Whether the test should be fuzzed under the address sanitizer.
    pub address: bool,
    /// Whether the test should be fuzzed under the thread sanitizer.
    pub thread: bool,
}

impl Sanitize {
    /// Returns the default sanitizer configuration based on crate feature flags.
    ///
    /// - `default-address` feature enables `address`
    /// - `default-thread` feature enables `thread`
    #[must_use]
    pub const fn defaults() -> Self {
        Self {
            address: cfg!(feature = "default-address"),
            thread: cfg!(feature = "default-thread"),
        }
    }

    /// Returns a sanitizer configuration with everything disabled.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            address: false,
            thread: false,
        }
    }

    /// Set the address sanitizer flag.
    #[must_use]
    pub const fn with_address(self, val: bool) -> Self {
        Self {
            address: val,
            ..self
        }
    }

    /// Set the thread sanitizer flag.
    #[must_use]
    pub const fn with_thread(self, val: bool) -> Self {
        Self {
            thread: val,
            ..self
        }
    }
}

impl core::fmt::Display for Sanitize {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut first = true;
        if self.address {
            write!(f, "address")?;
            first = false;
        }
        if self.thread {
            if !first {
                write!(f, ",")?;
            }
            write!(f, "thread")?;
        }
        if first {
            write!(f, "none")?;
        }
        Ok(())
    }
}

/// A registered fuzz test entry.
#[derive(Debug, Copy, Clone)]
pub struct Test {
    path: &'static str,
    sanitize: Sanitize,
    /// Number of parallel fuzzer jobs requested for this test.
    jobs: u32,
    /// Timeout in seconds requested for this test.
    timeout: u32,
}

/// Default number of parallel fuzzer jobs per test.
pub const DEFAULT_JOBS: u32 = 1;

/// Default timeout in seconds per test.
pub const DEFAULT_TIMEOUT: u32 = 5;

/// Serializable view of a [`Test`] with the package name split out.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TestInfo {
    /// Package name (e.g., `dataplane-net`).
    pub package: String,
    /// Test name without the crate prefix.
    pub name: String,
    /// Sanitizer configuration.
    pub sanitize: Sanitize,
    /// Requested parallel fuzzer jobs.
    pub jobs: u32,
    /// Requested timeout in seconds.
    pub timeout: u32,
}

impl Test {
    /// Create a new fuzz test entry.
    ///
    /// The `path` string should be the fully qualified path (`crate::module::function`).
    /// Typically constructed via `concat!(module_path!(), "::", stringify!(fn_name))`.
    #[must_use]
    pub const fn new(path: &'static str, sanitize: Sanitize, jobs: u32, timeout: u32) -> Self {
        Self {
            path,
            sanitize,
            jobs,
            timeout,
        }
    }

    /// The fully qualified path of the test function (e.g., `my_crate::module::test_name`).
    #[must_use]
    pub const fn path(&self) -> &'static str {
        self.path
    }

    /// The package name, derived from the crate portion of the path.
    ///
    /// Converts underscores to dashes (e.g., `dataplane_net` becomes `dataplane-net`).
    #[must_use]
    pub fn package(&self) -> String {
        self.path
            .split_once("::")
            .map_or_else(|| self.path.to_string(), |(pkg, _)| pkg.replace('_', "-"))
    }

    /// The test name without the crate prefix.
    #[must_use]
    pub fn name(&self) -> &str {
        self.path.split_once("::").map_or(self.path, |(_, name)| name)
    }

    /// The sanitizer configuration for this test.
    #[must_use]
    pub const fn sanitize(&self) -> &Sanitize {
        &self.sanitize
    }

    /// Number of parallel fuzzer jobs requested for this test.
    #[must_use]
    pub const fn jobs(&self) -> u32 {
        self.jobs
    }

    /// Timeout in seconds requested for this test.
    #[must_use]
    pub const fn timeout(&self) -> u32 {
        self.timeout
    }

    /// Convert to a serializable [`TestInfo`].
    #[must_use]
    pub fn info(&self) -> TestInfo {
        TestInfo {
            package: self.package(),
            name: self.name().to_string(),
            sanitize: self.sanitize,
            jobs: self.jobs,
            timeout: self.timeout,
        }
    }
}

impl core::fmt::Display for Test {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{} [{}] jobs={} timeout={}s",
            self.name(),
            self.sanitize,
            self.jobs,
            self.timeout,
        )
    }
}

/// The global distributed slice collecting all `#[fuzz]`-annotated tests in this binary.
#[distributed_slice]
pub static TESTS: [Test];

/// Entry point for the fuzz test harness.
///
/// Call this from a `harness = false` integration test:
///
/// ```ignore
/// // tests/fuzz/main.rs
/// fn main() {
///     fuzz_list::main();
/// }
/// ```
pub fn main() {
    harness::main();
}
