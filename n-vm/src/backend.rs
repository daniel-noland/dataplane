// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Hypervisor backend trait for pluggable VM lifecycle management.
//!
//! This module defines the [`HypervisorBackend`] trait that abstracts over
//! different hypervisors (cloud-hypervisor, QEMU, etc.) and the types
//! shared across all backends.
//!
//! The trait separates the hypervisor lifecycle into two phases:
//!
//! 1. [`launch`](HypervisorBackend::launch) -- spawn the hypervisor
//!    process, boot the VM, and start event monitoring.
//! 2. [`shutdown`](HypervisorBackend::shutdown) -- best-effort graceful
//!    shutdown of the VM and VMM.
//!
//! The intermediate state between these phases is captured by
//! [`LaunchedHypervisor`], which bundles the child process, a background
//! event-monitoring task, and a backend-specific lifecycle controller.

use n_vm_protocol::VsockChannel;

use crate::abort_on_drop::AbortOnDrop;
use crate::error::VmError;
use crate::vm::TestVmParams;

/// Verdict from the hypervisor indicating how the VM session ended.
///
/// Every hypervisor backend reduces its native event stream to this enum,
/// which represents the only two outcomes the test infrastructure cares
/// about: did the VM shut down cleanly, or not?
///
/// This replaces a bare `bool`, making call sites self-documenting and
/// preventing accidental inversion of success/failure logic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HypervisorVerdict {
    /// The hypervisor reported a clean, orderly shutdown with no guest
    /// panic or event-stream errors.
    CleanShutdown,
    /// The VM session ended abnormally -- a guest panic was detected, the
    /// event stream contained errors, or the stream ended without a clean
    /// shutdown event.
    Failure,
}

impl HypervisorVerdict {
    /// Returns `true` if the VM shut down cleanly.
    #[must_use]
    pub fn is_success(self) -> bool {
        matches!(self, Self::CleanShutdown)
    }
}

/// Resources produced by a successful hypervisor launch.
///
/// This struct is returned by [`HypervisorBackend::launch`] and consumed
/// by [`TestVm`](crate::vm::TestVm) to drive the rest of the VM lifetime.
///
/// The generic parameter `B` ties the event log and controller types to
/// the specific backend that produced them.
pub struct LaunchedHypervisor<B: HypervisorBackend> {
    /// The hypervisor child process handle.
    ///
    /// Ownership transfers to [`TestVm`](crate::vm::TestVm), which will
    /// wait for it during output collection.  The process should be
    /// spawned with `kill_on_drop(true)` so that unexpected drops don't
    /// leak a running VM.
    pub(crate) child: tokio::process::Child,

    /// Background task monitoring hypervisor lifecycle events.
    ///
    /// This task consumes the hypervisor's event stream (e.g.
    /// cloud-hypervisor's `--event-monitor` pipe, QEMU's QMP socket)
    /// and resolves to the collected event log and a
    /// [`HypervisorVerdict`].
    ///
    /// Wrapped in [`AbortOnDrop`] so that the monitoring task is
    /// cancelled if the [`TestVm`](crate::vm::TestVm) is dropped before
    /// [`collect`](crate::vm::TestVm::collect) is called.
    pub(crate) event_watcher: AbortOnDrop<(B::EventLog, HypervisorVerdict)>,

    /// Backend-specific handle for lifecycle control.
    ///
    /// For cloud-hypervisor this is the REST API client; for QEMU it
    /// would be a QMP socket connection.  Used by
    /// [`HypervisorBackend::shutdown`] during output collection.
    pub(crate) controller: B::Controller,
}

/// Trait abstracting over hypervisor implementations.
///
/// Each implementation encapsulates:
///
/// - **Configuration** -- translating [`TestVmParams`] into the
///   hypervisor's native format (JSON `VmConfig` for cloud-hypervisor,
///   command-line arguments for QEMU, etc.).
/// - **Process spawning and boot** -- starting the hypervisor process
///   and bringing the VM to a running state.
/// - **Event monitoring** -- watching for lifecycle events (clean
///   shutdown, guest panic, etc.) and reducing them to a
///   [`HypervisorVerdict`].
/// - **Lifecycle control** -- graceful shutdown of the VM and VMM.
///
/// The trait uses associated functions (no `&self`) because all
/// per-invocation state is passed explicitly through [`TestVmParams`]
/// and the [`LaunchedHypervisor::controller`].  Backend-level
/// configuration (binary paths, socket paths, etc.) is currently
/// provided by compile-time constants in [`n_vm_protocol`].
///
/// # Adding a new backend
///
/// Use the [`cloud_hypervisor`](crate::cloud_hypervisor) module as a
/// reference implementation.  The steps below outline the minimum work
/// required; see the cloud-hypervisor backend for concrete examples of
/// each step.
///
/// ## 1. Create the backend module
///
/// Create a new module directory (e.g. `src/qemu/mod.rs`) with at least:
///
/// - A **unit struct** (e.g. `pub struct Qemu;`) that serves as the type
///   tag for the backend.
/// - An **error submodule** (`error.rs`) defining a backend-specific
///   error enum (e.g. `QemuError`).  Only failure modes unique to the
///   backend belong here; generic errors like KVM accessibility and
///   process spawning already have variants in
///   [`VmError`](crate::error::VmError).
/// - An **event submodule** (if needed) for the backend's event/monitor
///   protocol (e.g. QMP for QEMU).
///
/// ## 2. Define associated types
///
/// Implement `HypervisorBackend` on the unit struct.  The two associated
/// types require some thought:
///
/// - **`EventLog`** -- a type that collects lifecycle events during the
///   VM's lifetime.  Must implement [`Display`](std::fmt::Display) (for
///   test failure diagnostics), [`Debug`], [`Default`] (for the fallback
///   path when the event watcher task panics), and [`Send`].
///
/// - **`Controller`** -- a handle for lifecycle control (e.g. a QMP
///   socket connection, a REST API client).  Must be [`Send`] because it
///   is held across `.await` points.  Typically wrapped in
///   `Arc<tokio::sync::Mutex<_>>` if the underlying client is not `Sync`.
///
/// ## 3. Implement `launch`
///
/// The [`launch`](Self::launch) method must:
///
/// 1. Run pre-flight checks.  Use the shared
///    [`check_kvm_accessible()`](crate::vm::check_kvm_accessible) utility
///    for the `/dev/kvm` check.
/// 2. Set up any monitoring channels (pipes, sockets, etc.) that the
///    hypervisor process needs.
/// 3. Spawn the hypervisor binary with `kill_on_drop(true)`, piped
///    stdout/stderr, and null stdin.
/// 4. Wait for the hypervisor to become ready.  Use the shared
///    [`wait_for_socket()`](crate::vm::wait_for_socket) utility if the
///    readiness signal is a socket appearing on the filesystem.
/// 5. Spawn a background event-monitoring task wrapped in
///    [`AbortOnDrop`](crate::abort_on_drop::AbortOnDrop) that resolves
///    to `(Self::EventLog, HypervisorVerdict)`.
/// 6. Return a [`LaunchedHypervisor`] with the child process, event
///    watcher, and controller.
///
/// Backend-specific errors should be defined in the backend's error
/// module and converted to [`VmError::Backend`](crate::error::VmError::Backend)
/// via a `From` impl:
///
/// ```ignore
/// impl From<QemuError> for VmError {
///     fn from(err: QemuError) -> Self {
///         VmError::Backend(Box::new(err))
///     }
/// }
/// ```
///
/// ## 4. Implement `shutdown`
///
/// The [`shutdown`](Self::shutdown) method is best-effort: log errors but
/// do not propagate them.  The VM has usually already powered off by the
/// time this is called (the init system calls `reboot(RB_POWER_OFF)`),
/// so failures are expected and harmless.
///
/// ## 5. Wire into the proc macro
///
/// The `#[in_vm]` proc macro (in `n-vm-macros`) generates a call to
/// [`run_container_tier`](crate::dispatch::run_container_tier) with an
/// explicit backend type parameter selected by an optional argument:
///
/// ```ignore
/// // #[in_vm] or #[in_vm(cloud_hypervisor)]
/// ::n_vm::run_container_tier::<::n_vm::CloudHypervisor, _>(test_fn);
///
/// // #[in_vm(qemu)]
/// ::n_vm::run_container_tier::<::n_vm::Qemu, _>(test_fn);
/// ```
///
/// To make a new backend available to the proc macro:
///
/// 1. Re-export the backend struct from `lib.rs` (e.g.
///    `pub use qemu::Qemu;`).
/// 2. Add an entry to the `KNOWN_BACKENDS` table in `n-vm-macros`
///    mapping a user-facing identifier (e.g. `"qemu"`) to the
///    fully-qualified type path (e.g. `"::n_vm::Qemu"`).
///
/// ## 6. Register in `lib.rs`
///
/// Add the backend module as a public module and re-export the backend
/// struct so that downstream crates and the proc macro can reference it
/// via `::n_vm::Qemu`.
///
/// ## Shared utilities
///
/// The following utilities in [`vm`](crate::vm) are available to all
/// backends:
///
/// - [`check_kvm_accessible()`](crate::vm::check_kvm_accessible) --
///   pre-flight `/dev/kvm` check.
/// - [`wait_for_socket()`](crate::vm::wait_for_socket) -- poll for a
///   socket to appear on the filesystem after process spawn.
///
/// ## Key differences: cloud-hypervisor vs QEMU
///
/// | Concern | cloud-hypervisor | QEMU |
/// |---------|-----------------|------|
/// | Boot model | Separate `create_vm` + `boot_vm` REST calls | Boots on process start |
/// | Control protocol | REST API over Unix socket | QMP (JSON-RPC) over Unix socket |
/// | Event monitoring | `--event-monitor fd=N` pipe | QMP async events |
/// | Shutdown | `shutdown_vm()` + `shutdown_vmm()` REST | `system_powerdown` + `quit` QMP |
/// | vsock | `VsockConfig` in `VmConfig` JSON | `-device vhost-vsock-pci,guest-cid=N` CLI |
/// | Hugepages | `MemoryConfig.hugepages` field | `-object memory-backend-file,mem-path=/dev/hugepages` |
#[expect(
    async_fn_in_trait,
    reason = "this trait is only used within the crate; auto-trait bounds on the \
              returned futures are not required"
)]
pub trait HypervisorBackend: Send + Sized + 'static {
    /// Human-readable name for this backend, used in log messages and
    /// diagnostic output (e.g. `"cloud-hypervisor"`, `"qemu"`).
    const NAME: &str;

    /// The collected event log produced by the backend's event monitor.
    ///
    /// For cloud-hypervisor this is `Vec<Event>` (the JSON event stream);
    /// for QEMU it would be the collected QMP events.
    ///
    /// The [`Display`](std::fmt::Display) bound is used by
    /// [`VmTestOutput`](crate::vm::VmTestOutput)'s `Display` impl to
    /// render the event log in test failure output.  Backends should
    /// produce a multi-line, human-readable representation of the event
    /// sequence suitable for inclusion in test diagnostics.
    type EventLog: std::fmt::Display + std::fmt::Debug + Default + Send + 'static;

    /// Backend-specific handle for VM lifecycle control.
    ///
    /// This type is stored in [`LaunchedHypervisor`] and passed to
    /// [`shutdown`](Self::shutdown).  It must be `Send` because it is
    /// held across `.await` points in
    /// [`TestVm::collect`](crate::vm::TestVm::collect).
    type Controller: Send + 'static;

    /// Spawns the hypervisor process, boots the VM, and starts background
    /// event monitoring.
    ///
    /// This method is responsible for the entire "bring-up" sequence:
    ///
    /// 1. Create any monitoring channels (pipes, sockets).
    /// 2. Spawn the hypervisor binary.
    /// 3. Wait for the hypervisor to be ready (API socket, QMP
    ///    greeting, etc.).
    /// 4. Configure and boot the VM (for hypervisors that separate
    ///    process start from VM boot, e.g. cloud-hypervisor's REST API;
    ///    QEMU boots on process start so this is implicit).
    /// 5. Spawn a background task that monitors lifecycle events and
    ///    produces a [`HypervisorVerdict`].
    ///
    /// All spawned tasks should be wrapped in [`AbortOnDrop`] and child
    /// processes should use `kill_on_drop(true)` to ensure cleanup on
    /// early return or panic.
    ///
    /// # Errors
    ///
    /// Returns [`VmError`] if any step of the launch sequence fails.
    async fn launch(params: &TestVmParams<'_>) -> Result<LaunchedHypervisor<Self>, VmError>;

    /// Performs a best-effort graceful shutdown of the VM and VMM.
    ///
    /// Called during [`TestVm::collect`](crate::vm::TestVm::collect)
    /// after the test has finished and event monitoring has completed.
    /// In the normal path the VM has already powered off (the init system
    /// calls `reboot(RB_POWER_OFF)`), so these calls may fail harmlessly.
    ///
    /// Implementations should log but not propagate errors, since this
    /// is a best-effort operation that must not prevent output collection.
    async fn shutdown(controller: &Self::Controller);

    /// Binds a listener for the given [`VsockChannel`] and spawns a
    /// background task that accepts a single connection and reads it to
    /// EOF, returning the contents as a `String`.
    ///
    /// The listener **must** be bound before the VM boots so that the
    /// guest-side `vsock::VsockStream::connect()` succeeds immediately.
    ///
    /// The mechanism for binding differs by backend:
    ///
    /// - **cloud-hypervisor** has a built-in vhost-user-vsock
    ///   implementation that maps guest vsock ports to Unix sockets at
    ///   `$VHOST_SOCKET_$PORT`.  The listener is a
    ///   [`tokio::net::UnixListener`] bound at
    ///   [`VsockChannel::listener_path()`].
    ///
    /// - **QEMU** uses the kernel's `vhost-vsock` module, which surfaces
    ///   guest vsock connections as `AF_VSOCK` sockets on the host.  The
    ///   listener is a [`tokio_vsock::VsockListener`] bound to the
    ///   channel's port on `VMADDR_CID_ANY`.
    ///
    /// # Errors
    ///
    /// Returns [`VmError::VsockBind`] if the listener cannot be bound.
    fn spawn_vsock_reader(channel: &VsockChannel) -> Result<AbortOnDrop<String>, VmError>;
}