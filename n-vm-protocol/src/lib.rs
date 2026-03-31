//! Shared protocol constants for the `n-vm` test infrastructure.
//!
//! This crate defines the implicit contract between the three tiers of the
//! nested test environment:
//!
//! 1. **Host** -- launches a Docker container via [`n-vm`](../n-vm).
//! 2. **Container** -- launches a VM via a pluggable
//!    [`HypervisorBackend`](../n_vm/backend/trait.HypervisorBackend.html)
//!    (cloud-hypervisor, QEMU, etc.).
//! 3. **VM guest** -- runs an init system ([`n-it`](../n-it)) that spawns the
//!    test binary.
//!
//! All magic numbers, filesystem paths, and environment variable names that
//! must agree across crate boundaries live here so that drift is caught at
//! compile time rather than at runtime.
//!
//! # Backend-specific constants
//!
//! Most constants in this crate are shared across all hypervisor backends
//! (filesystem layout, environment variables, vsock channels, etc.).
//! A small number are specific to a single backend and are annotated as
//! such in their documentation.  These exist here rather than in the
//! backend module because they define paths baked into the container image,
//! which is itself a cross-crate contract.

use std::path::PathBuf;

/// Platform string passed to the Docker engine when creating the container.
pub const CONTAINER_PLATFORM: &str = "linux/amd64";

// == Container mode ==
//
// The test infrastructure uses a locally-created empty Docker image and
// volume-mounts nix-built directory trees into it.  This eliminates
// version drift between the nix store paths baked into test binary
// rpaths and libraries shipped in an external container image.
//
// Two root directories are required:
//
// - **testroot** -- container-tier tools (hypervisor binaries,
//   virtiofsd, kernel image).  Subdirectories are mounted at their
//   standard container paths (`/bin`, `/lib`, etc.).
//
// - **vmroot** -- VM guest root filesystem shared via virtiofsd.
//   Contains the `n-it` init binary, glibc/libgcc runtime libraries,
//   and a `/nix -> /nix` symlink so guest processes can resolve nix
//   store rpaths through virtiofsd's `--no-sandbox` mode.
//
// The host's `/nix/store` is mounted read-only into the container so
// that the symlinks produced by nix's `symlinkJoin` resolve correctly.
//
// See `development/ideam.md` for the full design rationale.

/// Environment variable pointing to the resolved `testroot` directory.
///
/// When set, [`ScratchRoots::resolve`] uses this path instead of
/// auto-detecting the `testroot` symlink in the working directory.
///
/// The value must be an absolute path to the nix-built `testroot`
/// symlink (or the store path it resolves to).
pub const ENV_TEST_ROOT: &str = "N_VM_TEST_ROOT";

/// Environment variable pointing to the resolved `vmroot` directory.
///
/// When set, [`ScratchRoots::resolve`] uses this path instead of
/// auto-detecting the `vmroot` symlink in the working directory.
///
/// The value must be an absolute path to the nix-built `vmroot`
/// symlink (or the store path it resolves to).
pub const ENV_VM_ROOT: &str = "N_VM_VM_ROOT";

/// Resolved root directories for the test container infrastructure.
///
/// Returned by [`ScratchRoots::resolve`], which tries environment
/// variables first ([`ENV_TEST_ROOT`] / [`ENV_VM_ROOT`]) and falls
/// back to auto-detecting `testroot` and `vmroot` symlinks in the
/// current working directory.
#[derive(Debug, Clone)]
pub struct ScratchRoots {
    /// Absolute path to the `testroot` directory (container-tier tools).
    pub test_root: PathBuf,
    /// Absolute path to the `vmroot` directory (VM guest root filesystem).
    pub vm_root: PathBuf,
}

impl ScratchRoots {
    /// Resolves the `testroot` and `vmroot` directories.
    ///
    /// Resolution order:
    ///
    /// 1. **Environment variables** — if [`ENV_TEST_ROOT`] and
    ///    [`ENV_VM_ROOT`] are both set, their values are used.
    /// 2. **Working-directory auto-detection** — looks for `testroot`
    ///    and `vmroot` symlinks (or directories) in
    ///    [`std::env::current_dir`].
    ///
    /// # Errors
    ///
    /// - [`ScratchRootError::InvalidPath`] if an environment variable is
    ///   set but the path cannot be canonicalized.
    /// - [`ScratchRootError::NotFound`] if neither detection method
    ///   locates both roots.
    pub fn resolve() -> Result<Self, ScratchRootError> {
        if let Some(roots) = Self::from_env()? {
            return Ok(roots);
        }
        if let Some(roots) = Self::from_cwd() {
            return Ok(roots);
        }
        Err(ScratchRootError::NotFound)
    }

    /// Tries to resolve roots from [`ENV_TEST_ROOT`] and [`ENV_VM_ROOT`].
    ///
    /// Returns `Ok(None)` when either variable is absent or empty.
    fn from_env() -> Result<Option<Self>, ScratchRootError> {
        let test_root_raw = match std::env::var(ENV_TEST_ROOT) {
            Ok(v) if !v.is_empty() => v,
            _ => return Ok(None),
        };
        let vm_root_raw = match std::env::var(ENV_VM_ROOT) {
            Ok(v) if !v.is_empty() => v,
            _ => return Ok(None),
        };

        let test_root = std::fs::canonicalize(&test_root_raw).map_err(|source| {
            ScratchRootError::InvalidPath {
                var: ENV_TEST_ROOT,
                path: PathBuf::from(&test_root_raw),
                source,
            }
        })?;
        let vm_root = std::fs::canonicalize(&vm_root_raw).map_err(|source| {
            ScratchRootError::InvalidPath {
                var: ENV_VM_ROOT,
                path: PathBuf::from(&vm_root_raw),
                source,
            }
        })?;

        Ok(Some(Self { test_root, vm_root }))
    }

    /// Tries to find `testroot` and `vmroot` in the current working
    /// directory.
    ///
    /// Returns `None` if the CWD cannot be determined or either path
    /// does not exist.
    fn from_cwd() -> Option<Self> {
        let cwd = std::env::current_dir().ok()?;
        let test_root = std::fs::canonicalize(cwd.join("testroot")).ok()?;
        let vm_root = std::fs::canonicalize(cwd.join("vmroot")).ok()?;
        Some(Self { test_root, vm_root })
    }
}

/// Error resolving the test container root directories.
#[derive(Debug)]
pub enum ScratchRootError {
    /// An environment variable was set but the path it references
    /// cannot be canonicalized.
    InvalidPath {
        /// The environment variable name.
        var: &'static str,
        /// The raw path value from the environment.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },
    /// Neither environment variables nor working-directory
    /// auto-detection found `testroot` and `vmroot`.
    ///
    /// Run `just setup-roots` from the workspace root to create them,
    /// or set [`ENV_TEST_ROOT`] and [`ENV_VM_ROOT`] explicitly.
    NotFound,
}

impl std::fmt::Display for ScratchRootError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPath { var, path, .. } => {
                write!(f, "scratch root {var} = {path:?} is not accessible")
            }
            Self::NotFound => {
                write!(
                    f,
                    "could not find testroot/vmroot in the working directory \
                     and {ENV_TEST_ROOT}/{ENV_VM_ROOT} are not set; \
                     run `just setup-roots` from the workspace root"
                )
            }
        }
    }
}

impl std::error::Error for ScratchRootError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidPath { source, .. } => Some(source),
            Self::NotFound => None,
        }
    }
}

// == Environment variables ==

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

/// A vsock port number.
///
/// This newtype prevents accidentally passing an arbitrary [`u32`] (such as
/// a GID, file descriptor, or CID) where a vsock port is expected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VsockPort(u32);

impl VsockPort {
    /// The smallest port suitable for dynamic allocation.
    ///
    /// Ports below 1024 are conventionally reserved (similar to TCP/UDP
    /// well-known ports).  Dynamic allocators should pick from
    /// [`DYNAMIC_MIN`](Self::DYNAMIC_MIN)..=[`DYNAMIC_MAX`](Self::DYNAMIC_MAX).
    pub const DYNAMIC_MIN: Self = Self(1024);

    /// The largest port suitable for dynamic allocation.
    ///
    /// `VMADDR_PORT_ANY` (`u32::MAX`) is reserved as a wildcard.
    pub const DYNAMIC_MAX: Self = Self(u32::MAX - 1);

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

    /// The first CID available for guest use.
    ///
    /// CIDs 0–2 are reserved by the kernel; valid guest CIDs start at 3.
    pub const GUEST_MIN: Self = Self(3);

    /// The largest CID available for guest use.
    ///
    /// `VMADDR_CID_ANY` (`u32::MAX`) is reserved as a wildcard, so the
    /// maximum usable guest CID is `u32::MAX - 1`.  Although [`VsockCid`]
    /// stores a `u64`, the kernel's vhost-vsock ioctl and QEMU both
    /// truncate to `u32`.
    pub const GUEST_MAX: Self = Self(u32::MAX as u64 - 1);

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
///
/// **Deprecated in spirit** -- prefer [`VsockAllocation`] for new code.
/// This constant remains for backward compatibility with existing tests
/// that do not exercise parallel execution.  Production and CI paths
/// should always use a dynamically-allocated CID to avoid host-global
/// collisions when multiple VMs run concurrently.
pub const VM_GUEST_CID: VsockCid = VsockCid::new(3);

// ── Dynamic vsock resource allocation ────────────────────────────────
//
// Vsock CIDs and AF_VSOCK port bindings are host-global: they are NOT
// namespaced by containers, network namespaces, or cgroups.  When
// multiple test containers launch QEMU in parallel, each VM must use a
// unique CID and unique listener ports to avoid EADDRINUSE collisions.
//
// The types and constants below support dynamic allocation of these
// resources and a kernel-command-line protocol for passing the chosen
// port numbers into the guest.

/// Kernel command-line parameter: init-trace vsock port.
pub const CMDLINE_TRACE_PORT: &str = "n_it.trace_port";

/// Kernel command-line parameter: test-stdout vsock port.
pub const CMDLINE_STDOUT_PORT: &str = "n_it.stdout_port";

/// Kernel command-line parameter: test-stderr vsock port.
pub const CMDLINE_STDERR_PORT: &str = "n_it.stderr_port";

/// A complete set of dynamically-allocated vsock resources for a single
/// VM instance.
///
/// Vsock CIDs and `AF_VSOCK` port bindings are **host-global** — they
/// are *not* namespaced by containers, network namespaces, or cgroups.
/// When multiple test VMs run in parallel (even in separate containers),
/// each must use a unique CID and unique listener ports to avoid
/// `EADDRINUSE` collisions.
///
/// `VsockAllocation` bundles a randomly-chosen guest CID with three
/// vsock channels whose port numbers are also randomly chosen.  The
/// container tier generates one allocation per test run and threads it
/// through:
///
/// - The hypervisor configuration (CID for the vsock device).
/// - The vsock listeners (port numbers for `AF_VSOCK` or Unix sockets).
/// - The kernel command line (port numbers so `n-it` can connect back).
///
/// # Guest side
///
/// The guest init system recovers the port numbers by calling
/// [`VsockAllocation::parse_kernel_cmdline`] on the contents of
/// `/proc/cmdline`.  The guest does not need the CID — it always
/// connects to `VMADDR_CID_HOST`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VsockAllocation {
    /// The guest CID passed to the hypervisor's vsock device.
    pub cid: VsockCid,
    /// Channel for the init system's tracing output.
    pub init_trace: VsockChannel,
    /// Channel for the test process's stdout.
    pub test_stdout: VsockChannel,
    /// Channel for the test process's stderr.
    pub test_stderr: VsockChannel,
}

impl VsockAllocation {
    /// Creates an allocation using the legacy static values.
    ///
    /// This exists only for unit tests and single-VM scenarios where
    /// collision is impossible.  Production / CI code should use the
    /// random allocator in `n-vm`.
    pub const fn with_defaults() -> Self {
        Self {
            cid: VM_GUEST_CID,
            init_trace: VsockChannel::INIT_TRACE,
            test_stdout: VsockChannel::TEST_STDOUT,
            test_stderr: VsockChannel::TEST_STDERR,
        }
    }

    /// Formats the vsock port assignments as kernel command-line
    /// parameters.
    ///
    /// The returned string contains space-separated `key=value` pairs
    /// that the guest can parse from `/proc/cmdline` via
    /// [`parse_kernel_cmdline`](Self::parse_kernel_cmdline).
    pub fn kernel_cmdline_fragment(&self) -> String {
        format!(
            "{CMDLINE_TRACE_PORT}={} {CMDLINE_STDOUT_PORT}={} {CMDLINE_STDERR_PORT}={}",
            self.init_trace.port.as_raw(),
            self.test_stdout.port.as_raw(),
            self.test_stderr.port.as_raw(),
        )
    }

    /// Parses vsock port assignments from a kernel command-line string.
    ///
    /// This is the inverse of
    /// [`kernel_cmdline_fragment`](Self::kernel_cmdline_fragment).  The
    /// guest init system calls this with the contents of `/proc/cmdline`
    /// to discover which ports to connect to.
    ///
    /// The CID is set to [`VM_GUEST_CID`] because the guest does not
    /// need its own CID for outbound vsock connections (it always
    /// connects to `VMADDR_CID_HOST`).
    ///
    /// Returns `None` if any of the three port parameters are missing,
    /// cannot be parsed as `u32`, or would equal `VMADDR_PORT_ANY`.
    pub fn parse_kernel_cmdline(cmdline: &str) -> Option<Self> {
        let mut trace_port: Option<u32> = None;
        let mut stdout_port: Option<u32> = None;
        let mut stderr_port: Option<u32> = None;

        for token in cmdline.split_whitespace() {
            if let Some((key, value)) = token.split_once('=') {
                match key {
                    k if k == CMDLINE_TRACE_PORT => {
                        trace_port = value.parse().ok();
                    }
                    k if k == CMDLINE_STDOUT_PORT => {
                        stdout_port = value.parse().ok();
                    }
                    k if k == CMDLINE_STDERR_PORT => {
                        stderr_port = value.parse().ok();
                    }
                    _ => {}
                }
            }
        }

        // Filter out VMADDR_PORT_ANY (u32::MAX) — VsockPort::new would
        // panic on it.
        let trace_port = trace_port.filter(|&p| p != u32::MAX)?;
        let stdout_port = stdout_port.filter(|&p| p != u32::MAX)?;
        let stderr_port = stderr_port.filter(|&p| p != u32::MAX)?;

        Some(Self {
            // Guest doesn't need the real CID; it connects to CID_HOST.
            cid: VM_GUEST_CID,
            init_trace: VsockChannel {
                port: VsockPort::new(trace_port),
                label: "init-trace",
            },
            test_stdout: VsockChannel {
                port: VsockPort::new(stdout_port),
                label: "test-stdout",
            },
            test_stderr: VsockChannel {
                port: VsockPort::new(stderr_port),
                label: "test-stderr",
            },
        })
    }
}

impl std::fmt::Display for VsockAllocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "cid={}, trace={}, stdout={}, stderr={}",
            self.cid, self.init_trace.port, self.test_stdout.port, self.test_stderr.port,
        )
    }
}

// == Filesystem paths (inside the container / VM working directory) ==

/// Base directory for VM runtime artifacts (sockets, logs, etc.).
///
/// This directory is mounted as a tmpfs inside the container.
pub const VM_RUN_DIR: &str = "/vm";

/// Path to the virtiofsd Unix socket.
pub const VIRTIOFSD_SOCKET_PATH: &str = "/vm/virtiofsd.sock";

/// Path to the vhost-vsock Unix socket used by cloud-hypervisor.
pub const VHOST_VSOCK_SOCKET_PATH: &str = "/vm/vhost.vsock";

/// Path to the hypervisor control-plane Unix socket.
///
/// Cloud-hypervisor uses this path for its REST API socket
/// (`--api-socket`); QEMU would use it for its QMP socket
/// (`-chardev socket,path=...`).  Only one hypervisor runs per VM, so
/// both backends can share the same path.
pub const HYPERVISOR_API_SOCKET_PATH: &str = "/vm/hypervisor.sock";

/// Path to the serial/kernel console Unix socket.
pub const KERNEL_CONSOLE_SOCKET_PATH: &str = "/vm/kernel.sock";

/// Root filesystem share path exposed to the VM via virtiofs.
pub const VM_ROOT_SHARE_PATH: &str = "/vm.root";

/// The virtiofs tag used to identify the root filesystem inside the guest.
pub const VIRTIOFS_ROOT_TAG: &str = "root";

/// Well-known directory inside the VM guest where the test binary
/// directory is mounted.
///
/// The `vmroot` nix derivation pre-creates this directory so that Docker
/// can bind-mount the host-side binary directory at
/// `{VM_ROOT_SHARE_PATH}/{VM_TEST_BIN_DIR}` without needing to create
/// intermediate directories on the (read-only) nix store path.
///
/// Inside the VM guest, the test binary is executed as
/// `/{VM_TEST_BIN_DIR}/{binary_name}`.
pub const VM_TEST_BIN_DIR: &str = "test-bin";

// == Binary paths (inside the container) ==

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
///
/// **Backend-specific**: used only by the
/// [`CloudHypervisor`](../n_vm/cloud_hypervisor/struct.CloudHypervisor.html)
/// backend.
pub const CLOUD_HYPERVISOR_BINARY_PATH: &str = "/bin/cloud-hypervisor";

/// Path to the QEMU system emulator binary inside the container.
///
/// **Backend-specific**: used only by the
/// [`Qemu`](../n_vm/qemu/struct.Qemu.html) backend.
pub const QEMU_BINARY_PATH: &str = "/bin/qemu-system-x86_64";

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── VsockCid range constants ─────────────────────────────────────

    #[test]
    fn guest_min_cid_is_three() {
        assert_eq!(VsockCid::GUEST_MIN.as_raw(), 3);
    }

    #[test]
    fn guest_max_cid_is_below_u32_max() {
        assert_eq!(VsockCid::GUEST_MAX.as_raw(), u32::MAX as u64 - 1);
    }

    // ── VsockPort range constants ────────────────────────────────────

    #[test]
    fn dynamic_port_min_is_1024() {
        assert_eq!(VsockPort::DYNAMIC_MIN.as_raw(), 1024);
    }

    #[test]
    fn dynamic_port_max_is_below_u32_max() {
        assert_eq!(VsockPort::DYNAMIC_MAX.as_raw(), u32::MAX - 1);
    }

    // ── VsockAllocation round-trip ───────────────────────────────────

    #[test]
    fn kernel_cmdline_round_trip() {
        let alloc = VsockAllocation {
            cid: VsockCid::new(42),
            init_trace: VsockChannel {
                port: VsockPort::new(50_000),
                label: "init-trace",
            },
            test_stdout: VsockChannel {
                port: VsockPort::new(50_001),
                label: "test-stdout",
            },
            test_stderr: VsockChannel {
                port: VsockPort::new(50_002),
                label: "test-stderr",
            },
        };

        let fragment = alloc.kernel_cmdline_fragment();
        assert_eq!(
            fragment,
            "n_it.trace_port=50000 n_it.stdout_port=50001 n_it.stderr_port=50002",
        );

        // Embed in a realistic kernel cmdline with other parameters.
        let cmdline = format!(
            "console=ttyS0 ro rootfstype=virtiofs root=root {} init=/bin/n-it -- /test my_test",
            fragment,
        );

        let parsed = VsockAllocation::parse_kernel_cmdline(&cmdline)
            .expect("should parse successfully");

        assert_eq!(parsed.init_trace.port, alloc.init_trace.port);
        assert_eq!(parsed.test_stdout.port, alloc.test_stdout.port);
        assert_eq!(parsed.test_stderr.port, alloc.test_stderr.port);
    }

    #[test]
    fn parse_returns_none_on_missing_params() {
        let cmdline = "console=ttyS0 n_it.trace_port=50000 n_it.stdout_port=50001";
        assert!(
            VsockAllocation::parse_kernel_cmdline(cmdline).is_none(),
            "should fail when stderr port is missing",
        );
    }

    #[test]
    fn parse_returns_none_on_invalid_port() {
        let cmdline = "n_it.trace_port=abc n_it.stdout_port=50001 n_it.stderr_port=50002";
        assert!(
            VsockAllocation::parse_kernel_cmdline(cmdline).is_none(),
            "should fail when a port is not a valid u32",
        );
    }

    #[test]
    fn parse_rejects_vmaddr_port_any() {
        let cmdline = format!(
            "n_it.trace_port={} n_it.stdout_port=50001 n_it.stderr_port=50002",
            u32::MAX,
        );
        assert!(
            VsockAllocation::parse_kernel_cmdline(&cmdline).is_none(),
            "should reject VMADDR_PORT_ANY (u32::MAX)",
        );
    }

    #[test]
    fn with_defaults_matches_legacy_constants() {
        let alloc = VsockAllocation::with_defaults();
        assert_eq!(alloc.cid, VM_GUEST_CID);
        assert_eq!(alloc.init_trace, VsockChannel::INIT_TRACE);
        assert_eq!(alloc.test_stdout, VsockChannel::TEST_STDOUT);
        assert_eq!(alloc.test_stderr, VsockChannel::TEST_STDERR);
    }

    #[test]
    fn display_shows_all_fields() {
        let alloc = VsockAllocation::with_defaults();
        let display = format!("{alloc}");
        assert!(display.contains("cid=3"), "{display}");
        assert!(display.contains("trace=123456"), "{display}");
        assert!(display.contains("stdout=123457"), "{display}");
        assert!(display.contains("stderr=123458"), "{display}");
    }
}
