// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A library for working with and validating network data

#![deny(
    unsafe_code,
    missing_docs,
    clippy::all,
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
#![cfg_attr(not(unix), allow(unused))] // for wasm32 builds
#![cfg_attr(
    any(test, feature = "bolero"),
    allow(clippy::should_panic_without_expect)
)] // we panic in contract checks with simple unwrap()
#![cfg_attr(test,
    feature(
        // for distributed slice
        const_type_name,
        // to filter tests which are silly under the thread sanitizer
        cfg_sanitize
    ),
    // needed for distributed slice to function properly (only used for tests)
    allow(unsafe_code)
)]

pub mod addr_parse_error;
pub mod buffer;
pub mod checksum;
pub mod eth;
#[cfg(unix)]
pub mod flows;
pub mod headers;
pub mod icmp4;
pub mod icmp6;
pub mod icmp_any;
pub mod interface;
pub mod ip;
pub mod ip_auth;
pub mod ipv4;
pub mod ipv6;
#[cfg(unix)]
pub mod packet;
pub mod parse;
pub mod pci;
pub mod route;
pub mod tcp;
pub mod udp;
pub mod vlan;
pub mod vxlan;

// re-export
#[cfg(unix)]
pub use flows::flow_key::{
    self, ExtendedFlowKey, FlowKey, FlowKeyData, IcmpProtoKey, IpProtoKey, TcpProtoKey, UdpProtoKey,
};

#[cfg(test)]
mod fuzz {

    use linkme::distributed_slice;

    #[derive(Debug, Copy, Clone, serde::Serialize)]
    pub(crate) struct Sanitize {
        pub address: bool,
        pub thread: bool,
    }

    #[derive(Debug, Copy, Clone, serde::Serialize)]
    pub(crate) struct Test {
        test: &'static str,
        sanitize: Sanitize,
    }

    #[derive(Debug, Clone, serde::Serialize)]
    pub(crate) struct TestMsg {
        package: String,
        test: &'static str,
        sanitize: Sanitize,
    }

    impl Test {
        pub const fn new<F: Copy + FnOnce() -> R, R>(_: F) -> Self {
            let test = core::any::type_name::<F>();
            Self {
                test,
                sanitize: Sanitize {
                    address: true,
                    thread: false,
                },
            }
        }

        fn as_msg(&self) -> TestMsg {
            let Some((package, test)) = self.test.split_once("::") else {
                panic!("could not extract package and test name for fuzz::Test");
            };
            let package = package.replace('_', "-");
            TestMsg {
                test,
                package,
                sanitize: self.sanitize,
            }
        }
    }

    /// List of fuzz tests for this package
    #[distributed_slice]
    pub static TESTS: [Test];

    #[test]
    fn list_fuzz_tests() {
        let tests: Vec<_> = TESTS.static_slice().iter().map(Test::as_msg).collect();
        let msg = serde_json::to_string(tests.as_slice()).unwrap();
        println!("{msg}");
    }

    #[test]
    fn list_fuzz_tests_thread() {
        let tests: Vec<_> = TESTS
            .static_slice()
            .iter()
            .filter(|it| it.sanitize.thread)
            .map(Test::as_msg)
            .collect();
        let msg = serde_json::to_string(tests.as_slice()).unwrap();
        println!("{msg}");
    }
}
