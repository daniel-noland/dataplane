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
//! - [`VmError`] — failures in the **container → VM** tier
//!   ([`run_in_vm`](crate::run_in_vm) / [`TestVm`](crate::vm::TestVm)).
//! - [`ContainerError`] — failures in the **host → container** tier
//!   ([`run_test_in_vm`](crate::run_test_in_vm)).
//!
//! Cloud-hypervisor API errors are captured as `String` descriptions
//! because the generated client crate's error types do not implement
//! [`std::error::Error`].  Per project guidelines this is acceptable
//! when imposed by an external framework.

// ── VM tier errors ───────────────────────────────────────────────────

/// Errors that can occur while launching or managing a cloud-hypervisor VM
/// in the container tier.
///
/// Returned by [`TestVm::launch`](crate::vm::TestVm::launch) and
/// [`run_in_vm`](crate::run_in_vm).
#[derive(Debug, thiserror::Error)]
pub enum VmError {
    /// virtiofsd failed to start.
    #[error("failed to spawn virtiofsd")]
    VirtiofsdSpawn(#[source] std::io::Error),

    /// A vsock listener socket could not be bound.
    ///
    /// The container tier must bind Unix sockets for each
    /// [`VsockChannel`](n_vm_protocol::VsockChannel) *before* the VM boots.
    /// This error indicates one of those binds failed.
    #[error("failed to bind vsock listener for channel `{label}` at {path}")]
    VsockBind {
        /// Human-readable channel label (e.g. `"test-stdout"`).
        label: &'static str,
        /// Filesystem path that was passed to `bind()`.
        path: String,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// The event-monitor pipe between the host and cloud-hypervisor could
    /// not be created.
    #[error("failed to create event monitor pipe")]
    EventPipe(#[source] std::io::Error),

    /// The event-monitor pipe sender could not be converted to a blocking
    /// file descriptor for fd-mapping into the hypervisor process.
    #[error("failed to convert event monitor sender to blocking fd")]
    EventSenderFd(#[source] std::io::Error),

    /// `/dev/kvm` is missing or inaccessible inside the container.
    #[error("/dev/kvm is not accessible")]
    KvmNotAccessible(#[source] std::io::Error),

    /// File-descriptor mapping for the cloud-hypervisor child process
    /// failed (e.g. the `command-fds` crate detected an fd collision).
    ///
    /// The inner value is a stringified `command_fds::FdMappingCollision`
    /// because that type does not implement [`std::error::Error`].
    #[error("failed to set up fd mappings for cloud-hypervisor: {0}")]
    FdMapping(String),

    /// The cloud-hypervisor binary could not be spawned.
    #[error("failed to spawn cloud-hypervisor")]
    HypervisorSpawn(#[source] std::io::Error),

    /// The event-monitor pipe was not readable after the hypervisor
    /// process started, indicating the VMM did not emit its initial event.
    #[error("event monitor pipe not readable after hypervisor start")]
    EventMonitorNotReadable(#[source] std::io::Error),

    /// A required socket did not appear on the filesystem within the
    /// polling timeout.
    #[error("timed out waiting for socket {path} after {timeout_ms} ms")]
    SocketTimeout {
        /// The socket path that was being polled.
        path: String,
        /// Total time spent polling, in milliseconds.
        timeout_ms: u64,
    },

    /// An I/O error occurred while polling for a socket's existence.
    #[error("I/O error while waiting for socket {path}")]
    SocketPoll {
        /// The socket path that was being polled.
        path: String,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// The cloud-hypervisor API rejected the `create_vm` request.
    ///
    /// The `reason` field contains the stringified API error because the
    /// generated client crate's error type does not implement
    /// [`std::error::Error`].
    #[error("failed to create VM via hypervisor API: {reason}")]
    VmCreate {
        /// Stringified error from the cloud-hypervisor API client.
        reason: String,
    },

    /// The cloud-hypervisor API rejected the `boot_vm` request.
    ///
    /// See [`VmCreate`](Self::VmCreate) for why this uses a `String`.
    #[error("failed to boot VM via hypervisor API: {reason}")]
    VmBoot {
        /// Stringified error from the cloud-hypervisor API client.
        reason: String,
    },
}

// ── Container tier errors ────────────────────────────────────────────

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

    /// A required device node (e.g. `/dev/kvm`) is not accessible on the
    /// host.
    #[error("required device {path} is not accessible")]
    DeviceNotAccessible {
        /// The device path that could not be stat'd.
        path: String,
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
}