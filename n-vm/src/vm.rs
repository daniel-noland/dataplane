// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! VM lifecycle management for the container tier.
//!
//! # Error handling
//!
//! Functions that can fail return [`Result<_, VmError>`].  The
//! [`TestVm::collect`] phase is intentionally infallible -- individual
//! subsystem failures are recorded as degraded output (e.g.
//! `"!!!...UNAVAILABLE...!!!"`) rather than propagated, because the primary
//! goal is to give the developer as much diagnostic information as
//! possible even when things go wrong.
//!
//! This module handles launching virtiofsd, delegating hypervisor-specific
//! VM setup to a [`HypervisorBackend`], collecting output from all
//! subsystems, and returning a unified [`VmTestOutput`].
//!
//! Test process stdout and stderr are forwarded from the VM guest to the
//! container tier via dedicated [`VsockChannel`]s, giving the host clean
//! separation of the two channels.  The hypervisor's virtio-console is
//! expected to be disabled -- all test output travels over vsock.
//!
//! # Lifecycle
//!
//! The [`TestVm`] struct owns every long-lived resource (child processes,
//! background tasks, backend controller) and exposes a two-phase API:
//!
//! 1. [`TestVm::launch`] -- prepares the environment (virtiofsd, vsock
//!    listeners, hypervisor backend) and boots the VM.
//! 2. [`TestVm::collect`] -- waits for the test to finish, gathers output
//!    from all subsystems, and performs a clean shutdown.
//!
//! The convenience function [`run_in_vm`] wraps both phases for the
//! `#[in_vm]` macro.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use n_vm_protocol::{
    KERNEL_CONSOLE_SOCKET_PATH, VIRTIOFSD_BINARY_PATH, VIRTIOFSD_SOCKET_PATH, VIRTIOFS_ROOT_TAG,
    VM_ROOT_SHARE_PATH, VsockChannel,
};
use tokio::io::AsyncReadExt;
use tokio::task::JoinHandle;
use tracing::{error, warn};

use crate::abort_on_drop::AbortOnDrop;
use crate::backend::{HypervisorBackend, HypervisorVerdict};
use crate::error::VmError;

// ── Constants ────────────────────────────────────────────────────────

/// Maximum number of poll iterations before giving up on a socket.
const SOCKET_POLL_MAX_ATTEMPTS: u32 = 100;

/// Interval between socket existence checks.
const SOCKET_POLL_INTERVAL: Duration = Duration::from_millis(5);

// ── Utilities ────────────────────────────────────────────────────────

/// Polls the filesystem until `path` exists, returning an error on timeout
/// or I/O failure.
///
/// Several sockets created by hypervisors and virtiofsd appear
/// asynchronously after a process is spawned.  This helper encapsulates
/// the retry loop.
pub(crate) async fn wait_for_socket(path: impl AsRef<Path>) -> Result<(), VmError> {
    let path = path.as_ref();
    for _ in 0..SOCKET_POLL_MAX_ATTEMPTS {
        match tokio::fs::try_exists(path).await {
            Ok(true) => return Ok(()),
            Ok(false) => {
                tokio::time::sleep(SOCKET_POLL_INTERVAL).await;
            }
            Err(err) => {
                return Err(VmError::SocketPoll {
                    path: path.to_path_buf(),
                    source: err,
                });
            }
        }
    }
    Err(VmError::SocketTimeout {
        path: path.to_path_buf(),
        timeout: SOCKET_POLL_INTERVAL.saturating_mul(SOCKET_POLL_MAX_ATTEMPTS),
    })
}

/// Verifies that `/dev/kvm` is accessible inside the container.
///
/// Both cloud-hypervisor and QEMU require KVM for hardware-accelerated
/// virtualisation.  This pre-flight check runs before the hypervisor
/// process is spawned so that a missing or inaccessible `/dev/kvm`
/// produces a clear, early error rather than a cryptic child-process
/// failure.
///
/// # Errors
///
/// Returns [`VmError::KvmNotAccessible`] if `/dev/kvm` does not exist or
/// cannot be stat'd.
pub(crate) async fn check_kvm_accessible() -> Result<(), VmError> {
    match tokio::fs::try_exists("/dev/kvm").await {
        Ok(true) => Ok(()),
        Ok(false) => Err(VmError::KvmNotAccessible(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "/dev/kvm does not exist",
        ))),
        Err(err) => Err(VmError::KvmNotAccessible(err)),
    }
}

// ── ProcessOutput ────────────────────────────────────────────────────

/// Collected stdout and stderr from a child process.
///
/// This replaces the previous `(bool, String, String)` tuple return from
/// `collect_process_output`, making call sites self-documenting and
/// enabling reuse as a sub-struct inside [`VmTestOutput`].
pub struct ProcessOutput {
    /// Whether the process exited successfully (status code 0).
    ///
    /// Set to `false` if the process exited with a non-zero status or if
    /// its output could not be collected due to an I/O error.
    pub success: bool,
    /// Captured stdout as a lossy UTF-8 string.
    pub stdout: String,
    /// Captured stderr as a lossy UTF-8 string.
    ///
    /// On I/O failure during collection, this contains a diagnostic
    /// message instead of the actual process output.
    pub stderr: String,
}

impl ProcessOutput {
    /// Waits for a child process to exit and collects its stdout/stderr as
    /// UTF-8 strings.
    ///
    /// On I/O failure the process is treated as failed and the error is
    /// placed in the stderr string so that it still appears in
    /// [`VmTestOutput`]'s `Display` output.
    async fn from_child(child: tokio::process::Child, label: &str) -> Self {
        match child.wait_with_output().await {
            Ok(output) => Self {
                success: output.status.success(),
                stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            },
            Err(err) => {
                error!("failed to collect {label} output: {err}");
                Self {
                    success: false,
                    stdout: String::new(),
                    stderr: format!("!!!OUTPUT UNAVAILABLE: {err}!!!"),
                }
            }
        }
    }

    /// Awaits a [`JoinHandle<String>`], returning a fallback message on
    /// panic or cancellation.
    ///
    /// This is an associated function rather than a constructor because it
    /// returns a raw `String` (for use as a single output channel like
    /// init-system tracing or kernel console output), not a full
    /// [`ProcessOutput`].  It lives here because it is always used
    /// alongside [`from_child`](Self::from_child) during the output
    /// collection phase of [`TestVm::collect`].
    async fn join_task_or_fallback(handle: JoinHandle<String>, label: &str) -> String {
        match handle.await {
            Ok(output) => output,
            Err(err) => {
                error!("failed to join {label} task: {err}");
                format!("!!!{} UNAVAILABLE: {err}!!!", label.to_uppercase())
            }
        }
    }

    /// Formats the stdout and stderr sections with the given label prefix
    /// for inclusion in [`VmTestOutput`]'s `Display` output.
    fn fmt_sections(&self, f: &mut std::fmt::Formatter<'_>, label: &str) -> std::fmt::Result {
        writeln!(f, "--------------- {label} stdout ---------------")?;
        writeln!(f, "{}", self.stdout)?;
        writeln!(f, "--------------- {label} stderr ---------------")?;
        writeln!(f, "{}", self.stderr)
    }
}

// ── TestVmParams ─────────────────────────────────────────────────────

/// Parameters that vary per test invocation and feed into the VM
/// configuration.
///
/// This struct carries the test identity (binary path, binary name, test
/// name) to the [`HypervisorBackend`], which is responsible for
/// translating these into its native configuration format (e.g. a
/// cloud-hypervisor [`VmConfig`], QEMU command-line arguments, etc.).
///
/// # Usage
///
/// ```ignore
/// let params = TestVmParams { full_bin_path, bin_name, test_name };
/// let vm = TestVm::<MyBackend>::launch(&params).await?;
/// ```
pub struct TestVmParams<'a> {
    /// Full path to the test binary (e.g. `/path/to/deps/my_test-abc123`).
    pub full_bin_path: &'a Path,
    /// Short binary name (filename component only, e.g. `my_test-abc123`).
    pub bin_name: &'a str,
    /// Fully-qualified test name (e.g. `module::test_name`).
    pub test_name: &'a str,
}

// ── VmTestOutput ─────────────────────────────────────────────────────

/// Collected output from a test that ran inside a VM.
///
/// This struct aggregates all observable output from the three-tier test
/// execution (hypervisor events, kernel console, init system tracing, and the
/// test's own stdout/stderr).  Its [`Display`](std::fmt::Display) implementation
/// formats everything into labelled sections for easy reading in test failure
/// output.
///
/// The generic parameter `B` selects the hypervisor backend, which
/// determines the concrete type of the event log.
///
/// Test stdout and stderr are collected via dedicated
/// [`VsockChannel`]s, so they are cleanly separated from each other and
/// from the hypervisor process's own diagnostic output.
pub struct VmTestOutput<B: HypervisorBackend> {
    /// Whether the test passed and all infrastructure exited successfully.
    ///
    /// This is `true` only when **all** of the following hold:
    ///
    /// 1. The Rust test harness did not report failure in its stdout
    ///    summary line (`test result: FAILED`).
    /// 2. The hypervisor reported a clean VM shutdown (no guest panic, no
    ///    event-stream errors).
    /// 3. The hypervisor process exited with status 0.
    /// 4. The virtiofsd process exited with status 0.
    pub success: bool,
    /// Captured stdout and stderr from the test process (via vsock).
    pub test: ProcessOutput,
    /// Kernel serial console output (from the guest's `ttyS0`).
    pub console: String,
    /// Tracing output from the `n-it` init system, streamed via vsock.
    pub init_trace: String,
    /// Captured stdout, stderr, and exit status of the hypervisor process
    /// itself.
    pub hypervisor: ProcessOutput,
    /// Hypervisor lifecycle events collected during the VM's lifetime.
    ///
    /// The concrete type is determined by the backend (e.g.
    /// cloud-hypervisor's event monitor JSON stream, QEMU's QMP events).
    pub hypervisor_events: B::EventLog,
    /// Captured stdout, stderr, and exit status of the virtiofsd process.
    pub virtiofsd: ProcessOutput,
}

impl<B: HypervisorBackend> std::fmt::Display for VmTestOutput<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "=============== in_vm TEST RESULTS ===============")?;
        writeln!(
            f,
            "--------------- {} events ---------------",
            B::NAME
        )?;
        write!(f, "{}", self.hypervisor_events)?;
        self.hypervisor.fmt_sections(f, B::NAME)?;
        self.virtiofsd.fmt_sections(f, "virtiofsd")?;
        writeln!(f, "--------------- linux console ---------------")?;
        writeln!(f, "{}", self.console)?;
        writeln!(f, "--------------- init system ---------------")?;
        writeln!(f, "{}", self.init_trace)?;
        self.test.fmt_sections(f, "test")?;
        Ok(())
    }
}

// ── TestVm ───────────────────────────────────────────────────────────

/// Owns all long-lived resources for a running test VM.
///
/// The generic parameter `B` selects the hypervisor backend
/// (cloud-hypervisor, QEMU, etc.), which determines the concrete types
/// for lifecycle control and event monitoring.
///
/// The two-phase API ([`launch`](Self::launch) -> [`collect`](Self::collect))
/// separates concerns:
///
/// - **`launch`** handles environment preparation, process spawning, and VM
///   boot.  If any step fails it returns a [`VmError`] and all resources
///   created so far are cleaned up via `Drop` (child processes use
///   `kill_on_drop(true)`; spawned tasks are cancelled when the tokio
///   runtime shuts down).
///
/// - **`collect`** waits for the test to complete, gathers output from every
///   subsystem, performs a best-effort shutdown, and assembles a
///   [`VmTestOutput`].  It always succeeds -- individual subsystem failures
///   are recorded as degraded output rather than hard errors, because the
///   primary goal is to give the developer as much diagnostic information
///   as possible.
pub struct TestVm<B: HypervisorBackend> {
    /// The hypervisor child process.
    hypervisor: tokio::process::Child,
    /// The virtiofsd child process.
    virtiofsd: tokio::process::Child,
    /// Backend-specific handle for lifecycle control (e.g. REST API
    /// client for cloud-hypervisor, QMP connection for QEMU).
    controller: B::Controller,
    /// Background task watching hypervisor lifecycle events.
    ///
    /// Wrapped in [`AbortOnDrop`] so the task is automatically aborted if
    /// the `TestVm` is dropped without calling [`collect`](Self::collect)
    /// (e.g. due to a panic in surrounding code).
    event_watcher: AbortOnDrop<(B::EventLog, HypervisorVerdict)>,
    /// Background task collecting init system tracing output via vsock.
    init_trace: AbortOnDrop<String>,
    /// Background task collecting test process stdout via vsock.
    test_stdout: AbortOnDrop<String>,
    /// Background task collecting test process stderr via vsock.
    test_stderr: AbortOnDrop<String>,
    /// Background task collecting kernel serial console output.
    kernel_log: AbortOnDrop<String>,
}

impl<B: HypervisorBackend> TestVm<B> {
    /// Spawns a virtiofsd process that shares `path` into the VM as a
    /// read-only virtiofs mount.
    async fn launch_virtiofsd(path: impl AsRef<Path>) -> Result<tokio::process::Child, VmError> {
        let uid = nix::unistd::getuid().as_raw();
        let gid = nix::unistd::getgid().as_raw();
        tokio::process::Command::new(VIRTIOFSD_BINARY_PATH)
            .arg("--shared-dir")
            .arg(path.as_ref())
            .arg("--readonly")
            .arg("--tag")
            .arg(VIRTIOFS_ROOT_TAG)
            .arg("--socket-path")
            .arg(VIRTIOFSD_SOCKET_PATH)
            .arg("--announce-submounts")
            .arg("--sandbox=none")
            .arg("--rlimit-nofile=0")
            .arg(format!(
                "--translate-uid=squash-host:0:{uid}:{MAX}",
                MAX = u32::MAX
            ))
            .arg(format!(
                "--translate-gid=squash-host:0:{gid}:{MAX}",
                MAX = u32::MAX
            ))
            .stdin(Stdio::null())
            .stderr(Stdio::piped())
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(VmError::VirtiofsdSpawn)
    }

    /// Spawns a background task that connects to the kernel serial console
    /// socket and reads it to EOF.
    ///
    /// The console socket is created by the hypervisor after the VM boots,
    /// so the task polls for its existence before attempting to connect.
    fn spawn_kernel_log_reader() -> AbortOnDrop<String> {
        AbortOnDrop::spawn(async move {
            if let Err(e) = wait_for_socket(KERNEL_CONSOLE_SOCKET_PATH).await {
                return format!("!!!KERNEL LOG UNAVAILABLE: socket not ready: {e}!!!");
            }
            match tokio::net::UnixStream::connect(KERNEL_CONSOLE_SOCKET_PATH).await {
                Ok(mut stream) => {
                    let mut log = String::with_capacity(16_384);
                    if let Err(e) = stream.read_to_string(&mut log).await {
                        warn!("error reading kernel console: {e}");
                    }
                    log
                }
                Err(e) => format!("!!!KERNEL LOG UNAVAILABLE: connect failed: {e}!!!"),
            }
        })
    }

    /// Prepares the environment and boots the VM.
    ///
    /// This method orchestrates four phases:
    ///
    /// 1. [`launch_virtiofsd`](Self::launch_virtiofsd) -- share the
    ///    container filesystem into the VM.
    /// 2. [`B::spawn_vsock_reader`](HypervisorBackend::spawn_vsock_reader)
    ///    -- bind backend-specific vsock listeners for all channels.
    /// 3. [`B::launch`](HypervisorBackend::launch) -- delegate to the
    ///    backend for hypervisor-specific process spawning, VM
    ///    configuration, boot, and event monitoring.
    /// 4. [`spawn_kernel_log_reader`](Self::spawn_kernel_log_reader) --
    ///    start collecting kernel console output.
    ///
    /// All background tasks are wrapped in [`AbortOnDrop`], so if any phase
    /// fails (or the method panics), previously spawned tasks are
    /// automatically aborted when their handles drop.  Child processes use
    /// `kill_on_drop(true)` for the same guarantee.
    pub async fn launch(params: &TestVmParams<'_>) -> Result<Self, VmError> {
        let virtiofsd = Self::launch_virtiofsd(VM_ROOT_SHARE_PATH).await?;
        // All listeners must be bound *before* the VM boots so that the
        // guest-side vsock connections succeed immediately.  The listener
        // type is backend-specific: cloud-hypervisor uses Unix sockets,
        // QEMU uses AF_VSOCK via the kernel's vhost-vsock module.
        let init_trace = B::spawn_vsock_reader(&VsockChannel::INIT_TRACE)?;
        let test_stdout = B::spawn_vsock_reader(&VsockChannel::TEST_STDOUT)?;
        let test_stderr = B::spawn_vsock_reader(&VsockChannel::TEST_STDERR)?;

        let launched = B::launch(params).await?;

        let kernel_log = Self::spawn_kernel_log_reader();

        Ok(Self {
            hypervisor: launched.child,
            virtiofsd,
            controller: launched.controller,
            event_watcher: launched.event_watcher,
            init_trace,
            test_stdout,
            test_stderr,
            kernel_log,
        })
    }

    /// Waits for the test to finish and collects output from all subsystems.
    ///
    /// This method consumes the `TestVm`, shutting down the hypervisor and
    /// virtiofsd after collecting their output.  Individual subsystem
    /// failures are recorded as degraded output (e.g.
    /// `"!!!...UNAVAILABLE...!!!"`) rather than propagated as errors, because
    /// the primary goal is to give the developer as much diagnostic
    /// information as possible even when things go wrong.
    pub async fn collect(self) -> VmTestOutput<B> {
        let Self {
            hypervisor,
            virtiofsd,
            controller,
            event_watcher,
            init_trace,
            test_stdout,
            test_stderr,
            kernel_log,
        } = self;

        // Extract the inner JoinHandles from AbortOnDrop wrappers.
        // This disarms the abort-on-drop behavior -- from this point on,
        // we own the handles directly and will await them below.
        let event_watcher = event_watcher.into_inner();
        let init_trace = init_trace.into_inner();
        let test_stdout = test_stdout.into_inner();
        let test_stderr = test_stderr.into_inner();
        let kernel_log = kernel_log.into_inner();

        // The vsock readers complete when the guest-side streams close
        // (test process exits -> stdout/stderr close; n-it exits ->
        // init_trace closes).
        let init_trace =
            ProcessOutput::join_task_or_fallback(init_trace, "init system trace").await;
        let test_stdout = ProcessOutput::join_task_or_fallback(test_stdout, "test stdout").await;
        let test_stderr = ProcessOutput::join_task_or_fallback(test_stderr, "test stderr").await;

        // The event watcher completes when the hypervisor emits a
        // terminal event (Shutdown / Panic) or the pipe/socket closes.
        let (hypervisor_events, hypervisor_verdict) = match event_watcher.await {
            Ok(result) => result,
            Err(err) => {
                error!("hypervisor event watcher task failed: {err}");
                (B::EventLog::default(), HypervisorVerdict::Failure)
            }
        };

        // Best-effort shutdown BEFORE waiting for the hypervisor process
        // to exit.  In the normal path the VM has already powered off
        // (n-it calls reboot(RB_POWER_OFF) or aborts), so these calls
        // will fail harmlessly.  But if the guest init hangs or the
        // shutdown path fails, these calls break the deadlock that would
        // otherwise occur when `from_child` waits for the hypervisor
        // process to exit.
        B::shutdown(&controller).await;

        let hypervisor_output = ProcessOutput::from_child(hypervisor, B::NAME).await;

        // The kernel serial socket closes when the hypervisor exits.
        let kernel_log = ProcessOutput::join_task_or_fallback(kernel_log, "kernel log").await;

        let virtiofsd_output = ProcessOutput::from_child(virtiofsd, "virtiofsd").await;

        // The Rust test harness (invoked with `--format=terse`) writes a
        // summary line to stdout:
        //
        //   test result: ok. 1 passed; 0 failed; ...
        //   test result: FAILED. 0 passed; 1 failed; ...
        //
        // We check for the failure marker so that a test-level failure is
        // not masked by a clean infrastructure shutdown.  This is the most
        // reliable signal available without modifying the init system to
        // forward the test process's exit code over a dedicated channel.
        let test_passed = !test_stdout.contains("test result: FAILED");

        let test_output = ProcessOutput {
            // The test process runs inside the VM -- its exit code is not
            // directly observable from the container tier.  We rely on the
            // test harness summary line (checked via test_passed above) and
            // on n-it's behavior of aborting on test failure (which triggers
            // a guest panic detected by hypervisor_verdict).
            success: test_passed,
            stdout: test_stdout,
            stderr: test_stderr,
        };

        VmTestOutput {
            success: test_output.success
                && virtiofsd_output.success
                && hypervisor_verdict.is_success()
                && hypervisor_output.success,
            test: test_output,
            console: kernel_log,
            init_trace,
            hypervisor: hypervisor_output,
            hypervisor_events,
            virtiofsd: virtiofsd_output,
        }
    }
}

// ── run_in_vm ────────────────────────────────────────────────────────

/// Boots a VM using the given [`HypervisorBackend`] and runs the test
/// function inside it.
///
/// This is the **container-tier** entry point, called from the code generated
/// by `#[in_vm]` when `IN_TEST_CONTAINER=YES`.  It:
///
/// 1. Resolves the test identity from the type parameter and `argv[0]`.
/// 2. Delegates to [`TestVm::launch`] to prepare and boot the VM.
/// 3. Delegates to [`TestVm::collect`] to wait for the test and gather output.
///
/// The type parameter `B` selects the hypervisor backend.  The `#[in_vm]`
/// proc macro currently passes
/// [`CloudHypervisor`](crate::cloud_hypervisor::CloudHypervisor), but
/// callers can substitute any backend that implements
/// [`HypervisorBackend`].
///
/// The type parameter `F` is used only to derive the test name via
/// [`std::any::type_name`]; the function itself is never called in this tier.
///
/// # Errors
///
/// Returns [`VmError`] if any part of the VM launch sequence fails.
/// Output collection is best-effort and never fails -- see
/// [`TestVm::collect`].
pub async fn run_in_vm<B: HypervisorBackend, F: FnOnce()>(
    _: F,
) -> Result<VmTestOutput<B>, VmError> {
    let identity = crate::test_identity::TestIdentity::resolve::<F>();
    let test_name = identity.test_name;

    let full_bin_path = std::env::args().next().ok_or(VmError::MissingArgv)?;
    let (_, bin_name) =
        full_bin_path
            .rsplit_once("/")
            .ok_or_else(|| VmError::InvalidBinaryPath {
                path: PathBuf::from(&full_bin_path),
            })?;

    let params = TestVmParams {
        full_bin_path: Path::new(&full_bin_path),
        bin_name,
        test_name,
    };

    let vm = TestVm::<B>::launch(&params).await?;
    Ok(vm.collect().await)
}