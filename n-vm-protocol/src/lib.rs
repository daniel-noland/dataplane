//! Shared protocol constants for the `n-vm` test infrastructure.
//!
//! This crate defines the implicit contract between the three tiers of the
//! nested test environment:
//!
//! 1. **Host** -- launches a Docker container via [`n-vm`](../n-vm).
//! 2. **Container** -- launches a cloud-hypervisor VM via [`n-vm`](../n-vm).
//! 3. **VM guest** -- runs an init system ([`n-it`](../n-it)) that spawns the
//!    test binary.
//!
//! All magic numbers, filesystem paths, and environment variable names that
//! must agree across crate boundaries live here so that drift is caught at
//! compile time rather than at runtime.

use std::path::PathBuf;

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
pub const CONTAINER_PLATFORM: &str = "linux/amd64";

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

/// A vsock port number.
///
/// This newtype prevents accidentally passing an arbitrary [`u32`] (such as
/// a GID, file descriptor, or CID) where a vsock port is expected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VsockPort(u32);

impl VsockPort {
    /// Creates a new [`VsockPort`] from a raw port number.
    ///
    /// # Panics
    ///
    /// Panics if `port` is `u32::MAX` (`VMADDR_PORT_ANY`), which has
    /// special kernel semantics (wildcard / "assign any port") and must
    /// not be used as a concrete port number.
    #[must_use]
    pub const fn new(port: u32) -> Self {
        assert!(
            port != u32::MAX,
            "VMADDR_PORT_ANY (u32::MAX) cannot be used as a concrete vsock port"
        );
        Self(port)
    }

    /// Returns the raw `u32` port number.
    ///
    /// Use this at API boundaries that require a bare integer (e.g.
    /// [`vsock::VsockAddr::new`]).
    #[must_use]
    pub const fn as_raw(self) -> u32 {
        self.0
    }
}

impl std::fmt::Display for VsockPort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A vsock context identifier (CID).
///
/// This newtype prevents accidentally passing an arbitrary [`u64`] (such as
/// a byte count or timeout) where a vsock CID is expected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VsockCid(u64);

impl VsockCid {
    /// The hypervisor's CID (`VMADDR_CID_HYPERVISOR`).
    pub const HYPERVISOR: Self = Self(0);

    /// Loopback CID (`VMADDR_CID_LOCAL`), analogous to `127.0.0.1`.
    pub const LOCAL: Self = Self(1);

    /// The host CID (`VMADDR_CID_HOST`).
    pub const HOST: Self = Self(2);

    /// Creates a new [`VsockCid`] from a raw CID value.
    ///
    /// # Panics
    ///
    /// Panics if `cid` is 0 (`VMADDR_CID_HYPERVISOR`), 1
    /// (`VMADDR_CID_LOCAL`), or 2 (`VMADDR_CID_HOST`).  These CIDs have
    /// fixed kernel-level semantics and must not be used as arbitrary guest
    /// identifiers -- use the named constants [`Self::HYPERVISOR`],
    /// [`Self::LOCAL`], or [`Self::HOST`] instead.
    #[must_use]
    pub const fn new(cid: u64) -> Self {
        assert!(
            cid >= 3,
            "CIDs 0 (hypervisor), 1 (local), and 2 (host) are reserved; use the named constants instead"
        );
        Self(cid)
    }

    /// Returns the raw `u64` CID value.
    ///
    /// Use this at API boundaries that require a bare integer (e.g.
    /// cloud-hypervisor's [`VsockConfig`]).
    #[must_use]
    pub const fn as_raw(self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for VsockCid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A typed vsock communication channel between the VM guest and the
/// container host.
///
/// Each channel represents a unidirectional data stream from the VM guest
/// to the container tier, identified by a vsock port number.  The container
/// tier binds a Unix socket at [`listener_path`](Self::listener_path)
/// *before* booting the VM, and the guest connects to the corresponding
/// port via [`vsock::VsockStream`].
///
/// # Adding a new channel
///
/// Define a new `const` on this type.  Both sides (guest and container)
/// automatically pick up the port and listener path through the same
/// [`VsockChannel`] value, so there is exactly one place to update.
///
/// # Examples
///
/// Container side (bind before VM boot):
///
/// ```ignore
/// let path = VsockChannel::TEST_STDOUT.listener_path();
/// let listener = tokio::net::UnixListener::bind(&path)?;
/// ```
///
/// Guest side (connect after boot):
///
/// ```ignore
/// use tokio_vsock::VMADDR_CID_HOST;
/// let addr = vsock::VsockAddr::new(VMADDR_CID_HOST, VsockChannel::TEST_STDOUT.port.as_raw());
/// let stream = vsock::VsockStream::connect(&addr)?;
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VsockChannel {
    /// The vsock port number for this channel.
    pub port: VsockPort,
    /// A human-readable label used in log messages and error reports.
    pub label: &'static str,
}

impl VsockChannel {
    /// Channel for the init system's tracing data.
    ///
    /// The `n-it` init system connects to the host on this channel and
    /// streams structured [`tracing`] output so that the container tier
    /// can include it in [`VmTestOutput::init_trace`](../n_vm/struct.VmTestOutput.html).
    pub const INIT_TRACE: Self = Self {
        port: VsockPort::new(123_456),
        label: "init-trace",
    };

    /// Channel for the test process's **stdout**.
    ///
    /// The init system connects a vsock stream on this channel and passes
    /// the resulting fd as the child process's stdout.  The container tier
    /// binds a Unix listener at [`listener_path`](Self::listener_path)
    /// *before* booting the VM so that the connection succeeds immediately.
    pub const TEST_STDOUT: Self = Self {
        port: VsockPort::new(123_457),
        label: "test-stdout",
    };

    /// Channel for the test process's **stderr**.
    ///
    /// See [`TEST_STDOUT`](Self::TEST_STDOUT) for the general mechanism --
    /// this channel carries stderr instead of stdout, giving the host
    /// proper separation of the two streams.
    pub const TEST_STDERR: Self = Self {
        port: VsockPort::new(123_458),
        label: "test-stderr",
    };

    /// Returns the Unix socket path the container tier must bind for this
    /// channel.
    ///
    /// cloud-hypervisor creates a `<vhost_socket>_<port>` file for each
    /// vsock port that a guest connects to.  The host-side listener must
    /// bind to this path *before* the VM boots.
    pub fn listener_path(&self) -> PathBuf {
        PathBuf::from(format!("{VHOST_VSOCK_SOCKET_PATH}_{}", self.port.as_raw()))
    }
}

impl std::fmt::Display for VsockChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (vsock port {})", self.label, self.port.as_raw())
    }
}

/// The vsock context identifier (CID) assigned to the VM guest.
pub const VM_GUEST_CID: VsockCid = VsockCid::new(3);

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

// ── Binary paths (inside the container) ──────────────────────────────

/// Path to the Linux kernel image used to boot the VM.
///
/// This is a minimal `bzImage` bundled in the test container image.
pub const KERNEL_IMAGE_PATH: &str = "/bzImage";

/// Path to the `n-it` init system binary inside the container.
///
/// This binary is passed as the `init=` kernel command-line argument so
/// that it runs as PID 1 inside the VM guest.
pub const INIT_BINARY_PATH: &str = "/bin/n-it";

/// Path to the virtiofsd binary inside the container.
///
/// virtiofsd shares the container's filesystem into the VM via virtiofs.
pub const VIRTIOFSD_BINARY_PATH: &str = "/bin/virtiofsd";

/// Path to the cloud-hypervisor binary inside the container.
pub const CLOUD_HYPERVISOR_BINARY_PATH: &str = "/bin/cloud-hypervisor";