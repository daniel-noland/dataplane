// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dedicated error types for the `n-vm` test infrastructure.
//!
//! These replace the bare `.expect()` / `panic!()` calls that previously
//! made every failure path unrecoverable, giving callers the option to
//! handle errors via [`Result`] instead.
//!
//! # Design notes
//!
//! Each tier of the nested test environment has its own error enum:
//!
//! - [`VmError`] -- failures in the **container -> VM** tier
//!   ([`run_in_vm`](crate::run_in_vm) / [`TestVm`](crate::vm::TestVm)).
//! - [`ContainerError`] -- failures in the **host -> container** tier
//!   ([`run_test_in_vm`](crate::run_test_in_vm)).
//!
//! `VmError` contains only variants that are common to every hypervisor
//! backend (process spawning, socket polling, vsock, virtiofsd, etc.).
//! Backend-specific errors (e.g. cloud-hypervisor's event-monitor pipe or
//! REST API failures) are represented by the [`Backend`](VmError::Backend)
//! variant, which wraps a `Box<dyn Error>`.  Each backend module defines
//! its own error enum (e.g.
//! [`CloudHypervisorError`](crate::cloud_hypervisor::error::CloudHypervisorError))
//! that is boxed into this variant at the [`HypervisorBackend::launch`]
//! call site.
//!
//! [`HypervisorBackend::launch`]: crate::backend::HypervisorBackend::launch

use std::path::PathBuf;
use std::time::Duration;

/// Errors that can occur while launching or managing a VM in the
/// container tier.
///
/// This enum covers failure modes common to **all** hypervisor backends:
/// binary-path resolution, virtiofsd spawning, vsock listener binding,
/// KVM accessibility, hypervisor process spawning, and socket polling.
///
/// Backend-specific errors are wrapped in the [`Backend`](Self::Backend)
/// variant so that [`VmError`] does not need to know about any particular
/// hypervisor's internals.
///
/// Returned by [`TestVm::launch`](crate::vm::TestVm::launch) and
/// [`run_in_vm`](crate::run_in_vm).
#[derive(Debug, thiserror::Error)]
pub enum VmError {
    /// `argv[0]` was not available, so the test binary path could not be
    /// determined.
    ///
    /// This can happen if the process was spawned without arguments (e.g.
    /// via a bare `execve` with an empty argv array).
    #[error("argv[0] missing: cannot determine test binary path")]
    MissingArgv,

    /// The test binary path (from `argv[0]`) does not contain a `'/'`
    /// separator, so the binary name cannot be extracted.
    ///
    /// This can happen if the binary was invoked via `PATH` lookup without
    /// a directory component (e.g. `my_test` instead of `./my_test`).
    #[error("test binary path does not contain a '/' separator: {path:?}")]
    InvalidBinaryPath {
        /// The argv\[0\] value that could not be split.
        path: PathBuf,
    },

    /// virtiofsd failed to start.
    #[error("failed to spawn virtiofsd")]
    VirtiofsdSpawn(#[source] std::io::Error),

    /// A vsock listener socket could not be bound.
    ///
    /// The container tier must bind Unix sockets for each
    /// [`VsockChannel`](n_vm_protocol::VsockChannel) *before* the VM boots.
    /// This error indicates one of those binds failed.
    #[error("failed to bind vsock listener for channel `{label}` at {path:?}")]
    VsockBind {
        /// Human-readable channel label (e.g. `"test-stdout"`).
        label: &'static str,
        /// Filesystem path that was passed to `bind()`.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// `/dev/kvm` is missing or inaccessible inside the container.
    ///
    /// Both cloud-hypervisor and QEMU require KVM for hardware-accelerated
    /// virtualisation.  This error is raised during the pre-flight check
    /// before the hypervisor process is spawned.
    #[error("/dev/kvm is not accessible")]
    KvmNotAccessible(#[source] std::io::Error),

    /// `/dev/hugepages` is missing or inaccessible inside the container.
    ///
    /// Both cloud-hypervisor and QEMU require hugepage-backed memory for
    /// the VM guest (cloud-hypervisor via `MemoryConfig.hugepages`, QEMU
    /// via `-object memory-backend-file,mem-path=/dev/hugepages`).
    ///
    /// In scratch-mode containers, `/dev/hugepages` must be available as
    /// a hugetlbfs mount.  Privileged containers normally inherit this
    /// from the host, but if the host kernel does not have hugetlbfs
    /// mounted at `/dev/hugepages` or the mount is not propagated into
    /// the container, QEMU/cloud-hypervisor will crash immediately with
    /// an opaque error.
    ///
    /// This pre-flight check runs alongside [`KvmNotAccessible`] to
    /// surface the problem early with a clear message.
    #[error("/dev/hugepages is not accessible (hugetlbfs not mounted?)")]
    HugepagesNotAccessible(#[source] std::io::Error),

    /// The hypervisor binary could not be spawned.
    ///
    /// This is the `Command::spawn()` call for whatever hypervisor binary
    /// the active backend uses (e.g. `cloud-hypervisor`, `qemu-system-x86_64`).
    #[error("failed to spawn hypervisor process")]
    HypervisorSpawn(#[source] std::io::Error),

    /// A required socket did not appear on the filesystem within the
    /// polling timeout.
    ///
    /// Several sockets (API socket, virtiofsd socket, etc.) are created
    /// asynchronously by child processes.  This error means the polling
    /// loop in [`wait_for_socket`](crate::vm::wait_for_socket) exhausted
    /// its retry budget without finding the socket.
    #[error("timed out waiting for socket {path:?} after {timeout:?}")]
    SocketTimeout {
        /// The socket path that was being polled.
        path: PathBuf,
        /// Total time spent polling.
        timeout: Duration,
    },

    /// An I/O error occurred while polling for a socket's existence.
    #[error("I/O error while waiting for socket {path:?}")]
    SocketPoll {
        /// The socket path that was being polled.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// A backend-specific error occurred during the hypervisor launch
    /// sequence.
    ///
    /// Each [`HypervisorBackend`](crate::backend::HypervisorBackend)
    /// implementation defines its own error type covering failure modes
    /// unique to that hypervisor (e.g. cloud-hypervisor's event-monitor
    /// pipe setup, REST API calls; QEMU's QMP handshake, etc.).  Those
    /// errors are boxed into this variant so that [`VmError`] remains
    /// backend-agnostic.
    ///
    /// The full error chain is preserved through the
    /// [`source()`](std::error::Error::source) method on the inner error,
    /// so `{err:#?}` formatting will show the complete chain.
    #[error(transparent)]
    Backend(#[from] Box<dyn std::error::Error + Send + Sync>),
}

/// Errors that can occur while launching or managing a Docker container
/// in the host tier.
///
/// Returned by [`run_test_in_vm`](crate::run_test_in_vm).
#[derive(Debug, thiserror::Error)]
pub enum ContainerError {
    /// Could not read `/proc/self/exe` to determine the test binary path.
    #[error("failed to read /proc/self/exe")]
    BinaryPathRead(#[source] std::io::Error),

    /// Could not canonicalize the test binary's parent directory.
    #[error("failed to canonicalize test binary directory")]
    BinaryPathCanonicalize(#[source] std::io::Error),

    /// The test binary path (from `/proc/self/exe`) has no parent
    /// directory component.
    ///
    /// This is unexpected for a path returned by `readlink`, which should
    /// always be absolute.
    #[error("test binary path has no parent directory: {path}")]
    NoParentDirectory {
        /// The path that had no parent.
        path: PathBuf,
    },

    /// A filesystem path required for the container configuration is not
    /// valid UTF-8.
    ///
    /// Docker and the container runtime APIs require UTF-8 strings for
    /// mount paths and command arguments.
    #[error("path is not valid UTF-8: {path:?}")]
    NonUtf8Path {
        /// The path that could not be converted to a UTF-8 string.
        path: PathBuf,
    },

    /// A required device node (e.g. `/dev/kvm`) is not accessible on the
    /// host.
    #[error("required device {path:?} is not accessible")]
    DeviceNotAccessible {
        /// The device path that could not be stat'd.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// Could not connect to the Docker daemon.
    #[error("failed to connect to Docker daemon")]
    DockerConnect(#[source] bollard::errors::Error),

    /// Docker refused to create the container.
    #[error("failed to create Docker container")]
    ContainerCreate(#[source] bollard::errors::Error),

    /// Docker refused to start the container.
    #[error("failed to start Docker container")]
    ContainerStart(#[source] bollard::errors::Error),

    /// An error occurred while streaming container logs.
    #[error("error reading container log stream")]
    LogStream(#[source] bollard::errors::Error),

    /// The container inspection after exit did not include a
    /// [`ContainerState`](bollard::secret::ContainerState).
    #[error("container returned no state on inspection")]
    MissingState,

    /// Docker refused the post-exit container inspection.
    #[error("failed to inspect container after exit")]
    ContainerInspect(#[source] bollard::errors::Error),

    /// Docker refused to remove the container.
    #[error("failed to remove container")]
    ContainerRemove(#[source] bollard::errors::Error),

    /// A scratch-mode root directory environment variable is set but the
    /// path it references cannot be resolved.
    #[error("failed to resolve scratch root directory")]
    ScratchRootResolve(#[source] n_vm_protocol::ScratchRootError),

    /// The scratch Docker image could not be created locally.
    ///
    /// In scratch mode, a truly empty Docker image is created on-demand
    /// by importing an empty tar archive.  This error indicates that
    /// the import failed.
    #[error("failed to create scratch Docker image: {0}")]
    ScratchImageCreate(String),
}
