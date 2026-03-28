//! Shared protocol constants for the `n-vm` test infrastructure.
//!
//! This crate defines the implicit contract between the three tiers of the
//! nested test environment:
//!
//! 1. **Host** — launches a Docker container via [`n-vm`](../n-vm).
//! 2. **Container** — launches a cloud-hypervisor VM via [`n-vm`](../n-vm).
//! 3. **VM guest** — runs an init system ([`n-it`](../n-it)) that spawns the
//!    test binary.
//!
//! All magic numbers, filesystem paths, and environment variable names that
//! must agree across crate boundaries live here so that drift is caught at
//! compile time rather than at runtime.

// ── Container image ──────────────────────────────────────────────────

/// Docker image used by the host tier to launch the test container.
///
/// This image contains cloud-hypervisor, virtiofsd, the `n-it` init system
/// binary, and a minimal Linux kernel (`bzImage`).
///
/// TODO: make this configurable (e.g. via environment variable or builder
/// pattern) so that CI and local development can use different images.
pub const CONTAINER_IMAGE: &str = "ghcr.io/githedgehog/testn/n-vm:v0.0.9";

/// Platform string passed to the Docker engine when creating the container.
pub const CONTAINER_PLATFORM: &str = "x86-64";

// ── Environment variables ────────────────────────────────────────────

/// Environment variable set by the init system (`n-it`) inside the VM guest.
///
/// When this variable is set to [`ENV_MARKER_VALUE`], the `#[in_vm]` macro
/// knows it is running inside the VM and executes the test body directly.
pub const ENV_IN_VM: &str = "IN_VM";

/// Environment variable set by the container tier (`n-vm::run_test_in_vm`).
///
/// When this variable is set to [`ENV_MARKER_VALUE`], the `#[in_vm]` macro
/// knows it is running inside the Docker container and should launch a VM
/// via `n-vm::run_in_vm`.
pub const ENV_IN_TEST_CONTAINER: &str = "IN_TEST_CONTAINER";

/// The value used to mark both [`ENV_IN_VM`] and [`ENV_IN_TEST_CONTAINER`]
/// as active.
pub const ENV_MARKER_VALUE: &str = "YES";

// ── Vsock ────────────────────────────────────────────────────────────

/// The vsock port used by the init system to stream tracing data back to the
/// host.
///
/// This must match between the `n-it` init system (which connects to the host
/// on this port) and `n-vm::run_in_vm` (which listens for the connection).
pub const INIT_SYSTEM_VSOCK_PORT: u32 = 123_456;

/// The vsock context identifier (CID) assigned to the VM guest.
pub const VM_GUEST_CID: u64 = 3;

// ── Filesystem paths (inside the container / VM working directory) ───

/// Base directory for VM runtime artifacts (sockets, logs, etc.).
///
/// This directory is mounted as a tmpfs inside the container.
pub const VM_RUN_DIR: &str = "/vm";

/// Path to the virtiofsd Unix socket.
pub const VIRTIOFSD_SOCKET_PATH: &str = "/vm/virtiofsd.sock";

/// Path to the vhost-vsock Unix socket used by cloud-hypervisor.
pub const VHOST_VSOCK_SOCKET_PATH: &str = "/vm/vhost.vsock";

/// Path to the cloud-hypervisor API Unix socket.
pub const HYPERVISOR_API_SOCKET_PATH: &str = "/vm/hypervisor.sock";

/// Path to the serial/kernel console Unix socket.
pub const KERNEL_CONSOLE_SOCKET_PATH: &str = "/vm/kernel.sock";

/// Root filesystem share path exposed to the VM via virtiofs.
pub const VM_ROOT_SHARE_PATH: &str = "/vm.root";

/// The virtiofs tag used to identify the root filesystem inside the guest.
pub const VIRTIOFS_ROOT_TAG: &str = "root";

/// Returns the vhost-vsock listener socket path that includes the vsock port.
///
/// cloud-hypervisor creates a `<socket>_<port>` file for each vsock port that
/// a guest connects to.  The host-side listener must bind to this path
/// *before* the VM boots.
pub fn vhost_vsock_listener_path() -> String {
    format!("{VHOST_VSOCK_SOCKET_PATH}_{INIT_SYSTEM_VSOCK_PORT}")
}