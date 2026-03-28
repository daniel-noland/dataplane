//! Runtime support for the `#[in_vm]` test macro.
//!
//! This crate implements the two outer tiers of the nested test environment:
//!
//! - **Host tier** ([`run_test_in_vm`]) — launches a Docker container with the
//!   required devices and capabilities.
//! - **Container tier** ([`run_in_vm`]) — launches a cloud-hypervisor VM with
//!   virtiofsd, monitors hypervisor events, and collects test output.
//!
//! The innermost tier (the VM guest init system) is provided by the `n-it`
//! crate.

pub mod hypervisor;

mod container;
mod vm;

pub use container::{ContainerTestResult, run_test_in_vm};
pub use n_vm_macros::in_vm;
pub use vm::{VmTestOutput, run_in_vm};

/// Logs an error message and then panics with the same message.
///
/// This is the `n-vm` (host/container side) variant of the fatal macro.
/// Unlike the `n-it` version (which carefully flushes stdio and aborts to
/// trigger a guest panic), this version simply panics since it runs outside
/// the VM where normal panic handling is appropriate.
#[macro_export]
macro_rules! fatal {
    ($msg:expr) => {
        ::tracing::error!($msg);
        panic!($msg);
    };
}