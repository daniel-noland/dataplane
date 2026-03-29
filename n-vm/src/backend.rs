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
/// 1. Create a new module (e.g. `qemu.rs`).
/// 2. Define a unit struct implementing this trait.
/// 3. Implement the [`launch`](Self::launch) and
///    [`shutdown`](Self::shutdown) methods.
/// 4. Wire the backend into [`TestVm`](crate::vm::TestVm) (currently
///    hardcoded to
///    [`CloudHypervisor`](crate::cloud_hypervisor::CloudHypervisor)).
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
}