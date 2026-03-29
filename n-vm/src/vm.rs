//! Cloud-hypervisor VM lifecycle management for the container tier.
//!
//! # Error handling
//!
//! Functions that can fail return [`Result<_, VmError>`].  The
//! [`TestVm::collect`] phase is intentionally infallible — individual
//! subsystem failures are recorded as degraded output (e.g.
//! `"!!!…UNAVAILABLE…!!!"`) rather than propagated, because the primary
//! goal is to give the developer as much diagnostic information as
//! possible even when things go wrong.
//!
//! This module handles launching virtiofsd, configuring and booting a
//! cloud-hypervisor VM, collecting output from all subsystems, and returning
//! a unified [`VmTestOutput`].
//!
//! Test process stdout and stderr are forwarded from the VM guest to the
//! container tier via dedicated [`VsockChannel`]s, giving the host clean
//! separation of the two channels.  The cloud-hypervisor virtio-console
//! (`hvc0`) is disabled — all test output travels over vsock.
//!
//! # Lifecycle
//!
//! The [`TestVm`] struct owns every long-lived resource (child processes,
//! background tasks, API client) and exposes a two-phase API:
//!
//! 1. [`TestVm::launch`] — prepares the environment (virtiofsd, vsock
//!    listeners, cloud-hypervisor) and boots the VM.
//! 2. [`TestVm::collect`] — waits for the test to finish, gathers output
//!    from all subsystems, and performs a clean shutdown.
//!
//! The convenience function [`run_in_vm`] wraps both phases for the
//! `#[in_vm]` macro.

use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use cloud_hypervisor_client::apis::DefaultApi;
use cloud_hypervisor_client::models::console_config::Mode;
use cloud_hypervisor_client::models::{
    ConsoleConfig, CpuTopology, CpusConfig, FsConfig, LandlockConfig, MemoryConfig, NetConfig,
    PayloadConfig, PlatformConfig, VmConfig, VsockConfig,
};
use command_fds::{CommandFdExt, FdMapping};
use n_vm_protocol::{
    CLOUD_HYPERVISOR_BINARY_PATH, HYPERVISOR_API_SOCKET_PATH, INIT_BINARY_PATH,
    KERNEL_CONSOLE_SOCKET_PATH, KERNEL_IMAGE_PATH, VHOST_VSOCK_SOCKET_PATH,
    VIRTIOFSD_BINARY_PATH, VIRTIOFSD_SOCKET_PATH, VIRTIOFS_ROOT_TAG, VM_GUEST_CID,
    VM_ROOT_SHARE_PATH, VM_RUN_DIR, VsockChannel,
};
use tokio::io::AsyncReadExt;
use tokio::task::JoinHandle;
use tracing::{debug, error, warn};

use crate::abort_on_drop::AbortOnDrop;
use crate::error::VmError;
use crate::hypervisor::{self, HypervisorVerdict};

// ── Constants ────────────────────────────────────────────────────────

/// Maximum number of poll iterations before giving up on a socket.
const SOCKET_POLL_MAX_ATTEMPTS: u32 = 100;

/// Interval between socket existence checks.
const SOCKET_POLL_INTERVAL: Duration = Duration::from_millis(5);

/// Initial buffer capacity for vsock reader tasks.
const VSOCK_READER_CAPACITY: usize = 32_768;

/// The fd number used for the cloud-hypervisor event monitor pipe.
///
/// This is the child-side fd that cloud-hypervisor writes events to.
/// It must match the `--event-monitor fd=N` argument.
const EVENT_MONITOR_FD: i32 = 3;

// ── Helper: socket polling ───────────────────────────────────────────

/// Polls the filesystem until `path` exists, returning an error on timeout
/// or I/O failure.
///
/// Several sockets created by cloud-hypervisor and virtiofsd appear
/// asynchronously after a process is spawned.  This helper encapsulates
/// the retry loop.
async fn wait_for_socket(path: impl AsRef<Path>) -> Result<(), VmError> {
    let path = path.as_ref();
    for _ in 0..SOCKET_POLL_MAX_ATTEMPTS {
        match tokio::fs::try_exists(path).await {
            Ok(true) => return Ok(()),
            Ok(false) => {
                tokio::time::sleep(SOCKET_POLL_INTERVAL).await;
            }
            Err(err) => {
                return Err(VmError::SocketPoll {
                    path: path.display().to_string(),
                    source: err,
                });
            }
        }
    }
    Err(VmError::SocketTimeout {
        path: path.display().to_string(),
        timeout_ms: SOCKET_POLL_INTERVAL
            .saturating_mul(SOCKET_POLL_MAX_ATTEMPTS)
            .as_millis()
            .min(u128::from(u64::MAX)) as u64,
    })
}

// ── Helper: vsock reader ─────────────────────────────────────────────

/// Binds a Unix listener for the given [`VsockChannel`], then spawns a
/// task that accepts a single connection and reads it to EOF.
///
/// This pattern is shared by the init-system tracing channel, test stdout,
/// and test stderr — all of which are vsock streams that the VM guest
/// connects to via `vhost_vsock`.
///
/// The listener must be bound *before* the VM boots so that the guest-side
/// `vsock::VsockStream::connect()` succeeds immediately.
fn spawn_vsock_reader(channel: &VsockChannel) -> Result<AbortOnDrop<String>, VmError> {
    let path = channel.listener_path();
    let label = channel.label;
    let listen = tokio::net::UnixListener::bind(&path).map_err(|source| VmError::VsockBind {
        label,
        path: path.clone(),
        source,
    })?;
    Ok(AbortOnDrop::spawn(async move {
        let mut buf = Vec::with_capacity(VSOCK_READER_CAPACITY);
        let mut connection = match listen.accept().await {
            Ok((stream, _)) => stream,
            Err(e) => {
                error!("failed to accept {label} vsock connection: {e}");
                return format!(
                    "!!!{} UNAVAILABLE: accept failed: {e}!!!",
                    label.to_uppercase()
                );
            }
        };
        loop {
            match connection.read_buf(&mut buf).await {
                Ok(0) => break,
                Ok(_) => {}
                Err(e) => {
                    error!("error reading {label} vsock stream: {e}");
                    break;
                }
            }
        }
        String::from_utf8_lossy(&buf).into_owned()
    }))
}

// ── Helper: virtiofsd ────────────────────────────────────────────────

/// Spawns a virtiofsd process that shares `path` into the VM as a
/// read-only virtiofs mount.
async fn launch_virtiofsd(path: impl AsRef<str>) -> Result<tokio::process::Child, VmError> {
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

// ── Helper: hypervisor process ───────────────────────────────────────

/// Creates the event-monitor pipe, verifies `/dev/kvm`, spawns the
/// cloud-hypervisor binary, and waits for the API socket to appear.
///
/// Returns the child process handle and the event-monitor pipe receiver
/// (which is consumed by [`hypervisor::watch`]).
async fn spawn_hypervisor() -> Result<(tokio::process::Child, tokio::net::unix::pipe::Receiver), VmError> {
    let (event_sender, event_receiver) =
        tokio::net::unix::pipe::pipe().map_err(VmError::EventPipe)?;
    let event_sender = event_sender
        .into_blocking_fd()
        .map_err(VmError::EventSenderFd)?;

    match tokio::fs::try_exists("/dev/kvm").await {
        Ok(true) => {}
        Ok(false) => {
            return Err(VmError::KvmNotAccessible(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "/dev/kvm does not exist",
            )));
        }
        Err(err) => {
            return Err(VmError::KvmNotAccessible(err));
        }
    }

    let hypervisor = tokio::process::Command::new(CLOUD_HYPERVISOR_BINARY_PATH)
        .args([
            "--api-socket",
            format!("path={HYPERVISOR_API_SOCKET_PATH}").as_str(),
            "--event-monitor",
            format!("fd={EVENT_MONITOR_FD}").as_str(),
        ])
        .stdin(Stdio::null())
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .kill_on_drop(true)
        .fd_mappings(vec![FdMapping {
            parent_fd: event_sender,
            child_fd: EVENT_MONITOR_FD,
        }])
        .map_err(|e| VmError::FdMapping(format!("{e:?}")))?
        .spawn()
        .map_err(VmError::HypervisorSpawn)?;

    // The first VMM event becoming readable indicates the hypervisor
    // has started.  We then poll until the API socket appears on the
    // filesystem.
    event_receiver
        .readable()
        .await
        .map_err(VmError::EventMonitorNotReadable)?;
    wait_for_socket(HYPERVISOR_API_SOCKET_PATH).await?;

    Ok((hypervisor, event_receiver))
}

// ── Helper: kernel console reader ────────────────────────────────────

/// Spawns a background task that connects to the kernel serial console
/// socket and reads it to EOF.
///
/// The console socket is created by cloud-hypervisor after the VM boots,
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

// ── Helper: process output collection ────────────────────────────────

/// Waits for a child process to exit and collects its stdout/stderr as
/// UTF-8 strings.
///
/// Returns `(exit_ok, stdout, stderr)`.  On I/O failure the process is
/// treated as failed and the error is placed in the stderr string so that
/// it still appears in [`VmTestOutput`]'s `Display` output.
async fn collect_process_output(
    child: tokio::process::Child,
    label: &str,
) -> (bool, String, String) {
    match child.wait_with_output().await {
        Ok(output) => (
            output.status.success(),
            String::from_utf8_lossy(&output.stdout).into_owned(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        ),
        Err(err) => {
            error!("failed to collect {label} output: {err}");
            (
                false,
                String::new(),
                format!("!!!OUTPUT UNAVAILABLE: {err}!!!"),
            )
        }
    }
}

/// Awaits a [`JoinHandle<String>`], returning a fallback message on panic
/// or cancellation.
async fn join_or_fallback(handle: JoinHandle<String>, label: &str) -> String {
    match handle.await {
        Ok(output) => output,
        Err(err) => {
            error!("failed to join {label} task: {err}");
            format!(
                "!!!{} UNAVAILABLE: {err}!!!",
                label.to_uppercase()
            )
        }
    }
}

// ── VM config factory ────────────────────────────────────────────────

/// Parameters that vary per test invocation and feed into the VM
/// configuration.
///
/// Everything else in the [`VmConfig`] is an infrastructure default
/// that can eventually be overridden via a builder pattern.
pub struct TestVmParams<'a> {
    /// Full path to the test binary (e.g. `/path/to/deps/my_test-abc123`).
    pub full_bin_path: &'a str,
    /// Short binary name (filename component only, e.g. `my_test-abc123`).
    pub bin_name: &'a str,
    /// Fully-qualified test name (e.g. `module::test_name`).
    pub test_name: &'a str,
}

/// Builds the cloud-hypervisor [`VmConfig`] for a test run.
///
/// This function separates the **what** (infrastructure defaults such as
/// CPU topology, memory size, network layout) from the **where** (test
/// binary path, test name) so that the lifecycle code in [`TestVm`] stays
/// focused on resource management.
///
/// The virtio-console is disabled (`Mode::Off`) because test stdout/stderr
/// are forwarded via dedicated [`VsockChannel`]s instead.
fn build_vm_config(params: &TestVmParams<'_>) -> VmConfig {
    let TestVmParams {
        full_bin_path,
        bin_name,
        test_name,
    } = params;

    VmConfig {
        payload: PayloadConfig {
            firmware: None,
            kernel: Some(KERNEL_IMAGE_PATH.into()),
            cmdline: Some(format!(
                "iommu=on \
                 intel_iommu=on \
                 amd_iommu=on \
                 vfio.enable_unsafe_noiommu_mode=1 \
                 earlyprintk=ttyS0 \
                 console=ttyS0 \
                 ro \
                 rootfstype=virtiofs \
                 root=root \
                 default_hugepagesz=2M \
                 hugepagesz=2M \
                 hugepages=16 \
                 init={INIT_BINARY_PATH} \
                 -- {full_bin_path} {test_name} --exact --no-capture --format=terse"
            )),
            ..Default::default()
        },
        vsock: Some(VsockConfig {
            cid: VM_GUEST_CID as _,
            socket: VHOST_VSOCK_SOCKET_PATH.into(),
            pci_segment: Some(0),
            ..Default::default()
        }),
        cpus: Some(CpusConfig {
            boot_vcpus: 6,
            max_vcpus: 6,
            topology: Some(CpuTopology {
                threads_per_core: Some(2),
                cores_per_die: Some(1),
                dies_per_package: Some(3),
                packages: Some(1),
            }),
            ..Default::default()
        }),
        memory: Some(MemoryConfig {
            size: 512 * 1024 * 1024, // 512 MiB
            mergeable: Some(true),
            shared: Some(true),
            hugepages: Some(true),
            hugepage_size: Some(2 * 1024 * 1024), // 2 MiB
            thp: Some(true),
            ..Default::default()
        }),
        net: Some(vec![
            NetConfig {
                tap: Some("mgmt".into()),
                ip: Some("fe80::ffff:1".into()),
                mask: Some("ffff:ffff:ffff:ffff::".into()),
                mac: Some("02:DE:AD:BE:EF:01".into()),
                mtu: Some(1500),
                id: Some("mgmt".into()),
                pci_segment: Some(0),
                queue_size: Some(512),
                ..Default::default()
            },
            NetConfig {
                tap: Some("fabric1".into()),
                ip: Some("fe80::1".into()),
                mask: Some("ffff:ffff:ffff:ffff::".into()),
                mac: Some("02:CA:FE:BA:BE:01".into()),
                mtu: Some(9500),
                id: Some("fabric1".into()),
                pci_segment: Some(1),
                queue_size: Some(8192),
                ..Default::default()
            },
            NetConfig {
                tap: Some("fabric2".into()),
                ip: Some("fe80::2".into()),
                mask: Some("ffff:ffff:ffff:ffff::".into()),
                mac: Some("02:CA:FE:BA:BE:02".into()),
                mtu: Some(9500),
                id: Some("fabric2".into()),
                pci_segment: Some(1),
                queue_size: Some(8192),
                ..Default::default()
            },
        ]),
        fs: Some(vec![FsConfig {
            tag: VIRTIOFS_ROOT_TAG.into(),
            socket: VIRTIOFSD_SOCKET_PATH.into(),
            num_queues: 1,
            queue_size: 1024,
            id: Some(VIRTIOFS_ROOT_TAG.into()),
            ..Default::default()
        }]),
        // The virtio-console is disabled: test stdout/stderr travel over
        // dedicated VsockChannels (TEST_STDOUT / TEST_STDERR).
        console: Some(ConsoleConfig::new(Mode::Off)),
        serial: Some(ConsoleConfig {
            mode: Mode::Socket,
            socket: Some(KERNEL_CONSOLE_SOCKET_PATH.into()),
            ..Default::default()
        }),
        iommu: Some(false),
        watchdog: Some(true),
        platform: Some(PlatformConfig {
            serial_number: Some("dataplane-test".into()),
            uuid: Some("dff9c8dd-492d-4148-a007-7931f94db852".into()), // arbitrary uuid4
            oem_strings: Some(vec![
                format!("exe={bin_name}"),
                format!("test={test_name}"),
            ]),
            num_pci_segments: Some(2),
            ..Default::default()
        }),
        pvpanic: Some(true),
        landlock_enable: Some(true),
        landlock_rules: Some(vec![LandlockConfig {
            path: VM_RUN_DIR.into(),
            access: "rw".into(),
        }]),
        ..Default::default()
    }
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
/// Test stdout and stderr are collected via dedicated
/// [`VsockChannel`]s, so they are cleanly separated from each other and
/// from the cloud-hypervisor process's own diagnostic output.
pub struct VmTestOutput {
    /// Whether the test passed and all infrastructure exited successfully.
    ///
    /// This is `true` only when **all** of the following hold:
    ///
    /// 1. The Rust test harness did not report failure in its stdout
    ///    summary line (`test result: FAILED`).
    /// 2. The cloud-hypervisor VM shut down cleanly (no guest panic, no
    ///    event-stream errors).
    /// 3. The cloud-hypervisor process exited with status 0.
    /// 4. The virtiofsd process exited with status 0.
    pub success: bool,
    /// Captured stdout from the test process (via vsock).
    pub stdout: String,
    /// Captured stderr from the test process (via vsock).
    pub stderr: String,
    /// Kernel serial console output (from the guest's `ttyS0`).
    pub console: String,
    /// Tracing output from the `n-it` init system, streamed via vsock.
    pub init_trace: String,
    /// Captured stdout from the cloud-hypervisor process itself.
    pub hypervisor_stdout: String,
    /// Captured stderr from the cloud-hypervisor process itself.
    pub hypervisor_stderr: String,
    /// Captured stdout from the virtiofsd process.
    pub virtiofsd_stdout: String,
    /// Captured stderr from the virtiofsd process.
    pub virtiofsd_stderr: String,
    /// Cloud-hypervisor lifecycle events collected during the VM's lifetime.
    pub hypervisor_events: Vec<hypervisor::Event>,
}

impl std::fmt::Display for VmTestOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "=============== in_vm TEST RESULTS ===============")?;
        writeln!(f, "--------------- cloud-hypervisor events ---------------")?;
        for event in &self.hypervisor_events {
            writeln!(
                f,
                "[{:?}] {:?} - {:?} {:?}",
                event.timestamp, event.source, event.event, event.properties
            )?;
        }
        writeln!(f, "--------------- cloud-hypervisor stdout ---------------")?;
        writeln!(f, "{}", self.hypervisor_stdout)?;
        writeln!(f, "--------------- cloud-hypervisor stderr ---------------")?;
        writeln!(f, "{}", self.hypervisor_stderr)?;
        writeln!(f, "--------------- virtiofsd stdout ---------------")?;
        writeln!(f, "{}", self.virtiofsd_stdout)?;
        writeln!(f, "--------------- virtiofsd stderr ---------------")?;
        writeln!(f, "{}", self.virtiofsd_stderr)?;
        writeln!(f, "--------------- linux console ---------------")?;
        writeln!(f, "{}", self.console)?;
        writeln!(f, "--------------- init system ---------------")?;
        writeln!(f, "{}", self.init_trace)?;
        writeln!(f, "--------------- test stdout ---------------")?;
        writeln!(f, "{}", self.stdout)?;
        writeln!(f, "--------------- test stderr ---------------")?;
        writeln!(f, "{}", self.stderr)?;
        Ok(())
    }
}

// ── TestVm ───────────────────────────────────────────────────────────

/// Owns all long-lived resources for a running test VM.
///
/// The two-phase API ([`launch`](Self::launch) → [`collect`](Self::collect))
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
///   [`VmTestOutput`].  It always succeeds — individual subsystem failures
///   are recorded as degraded output rather than hard errors, because the
///   primary goal is to give the developer as much diagnostic information
///   as possible.
pub struct TestVm {
    /// The cloud-hypervisor child process.
    hypervisor: tokio::process::Child,
    /// The virtiofsd child process.
    virtiofsd: tokio::process::Child,
    /// The cloud-hypervisor REST API client (behind a mutex because the
    /// generated client takes `&self`).
    client: Arc<tokio::sync::Mutex<dyn DefaultApi>>,
    /// Background task watching hypervisor lifecycle events.
    ///
    /// Wrapped in [`AbortOnDrop`] so the task is automatically aborted if
    /// the `TestVm` is dropped without calling [`collect`](Self::collect)
    /// (e.g. due to a panic in surrounding code).
    event_watcher: AbortOnDrop<(Vec<hypervisor::Event>, HypervisorVerdict)>,
    /// Background task collecting init system tracing output via vsock.
    init_trace: AbortOnDrop<String>,
    /// Background task collecting test process stdout via vsock.
    test_stdout: AbortOnDrop<String>,
    /// Background task collecting test process stderr via vsock.
    test_stderr: AbortOnDrop<String>,
    /// Background task collecting kernel serial console output.
    kernel_log: AbortOnDrop<String>,
}

impl TestVm {
    /// Prepares the environment and boots the VM.
    ///
    /// This method orchestrates five focused phases, each delegated to a
    /// helper function:
    ///
    /// 1. [`launch_virtiofsd`] — share the container filesystem into the VM.
    /// 2. [`spawn_vsock_reader`] — bind vsock listeners for all channels.
    /// 3. [`spawn_hypervisor`] — create the event pipe, verify `/dev/kvm`,
    ///    spawn cloud-hypervisor, and wait for the API socket.
    /// 4. Create and boot the VM via the hypervisor REST API.
    /// 5. [`spawn_kernel_log_reader`] — start collecting kernel console output.
    ///
    /// All background tasks are wrapped in [`AbortOnDrop`], so if any phase
    /// fails (or the method panics), previously spawned tasks are
    /// automatically aborted when their handles drop.  Child processes use
    /// `kill_on_drop(true)` for the same guarantee.
    pub async fn launch(params: &TestVmParams<'_>) -> Result<Self, VmError> {
        // ── Phase 1: Launch virtiofsd ────────────────────────────────
        let virtiofsd = launch_virtiofsd(VM_ROOT_SHARE_PATH).await?;

        // ── Phase 2: Bind vsock listeners ────────────────────────────
        // All listeners must be bound *before* the VM boots so that the
        // guest-side vsock connections succeed immediately.
        let init_trace = spawn_vsock_reader(&VsockChannel::INIT_TRACE)?;
        let test_stdout = spawn_vsock_reader(&VsockChannel::TEST_STDOUT)?;
        let test_stderr = spawn_vsock_reader(&VsockChannel::TEST_STDERR)?;

        // ── Phase 3: Spawn cloud-hypervisor ──────────────────────────
        let (hypervisor, event_receiver) = spawn_hypervisor().await?;

        // ── Phase 4: Create and boot the VM ──────────────────────────
        let config = build_vm_config(params);

        let client = Arc::new(tokio::sync::Mutex::new(
            cloud_hypervisor_client::socket_based_api_client(HYPERVISOR_API_SOCKET_PATH),
        ));

        client
            .lock()
            .await
            .create_vm(config)
            .await
            .map_err(|e| VmError::VmCreate {
                reason: format!("{e:?}"),
            })?;

        let event_watcher = AbortOnDrop::spawn(hypervisor::watch(event_receiver));

        client
            .lock()
            .await
            .boot_vm()
            .await
            .map_err(|e| VmError::VmBoot {
                reason: format!("{e:?}"),
            })?;

        // ── Phase 5: Start kernel console reader ─────────────────────
        let kernel_log = spawn_kernel_log_reader();

        Ok(Self {
            hypervisor,
            virtiofsd,
            client,
            event_watcher,
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
    /// `"!!!…UNAVAILABLE…!!!"`) rather than propagated as errors, because
    /// the primary goal is to give the developer as much diagnostic
    /// information as possible even when things go wrong.
    pub async fn collect(self) -> VmTestOutput {
        let Self {
            hypervisor,
            virtiofsd,
            client,
            event_watcher,
            init_trace,
            test_stdout,
            test_stderr,
            kernel_log,
        } = self;

        // Extract the inner JoinHandles from AbortOnDrop wrappers.
        // This disarms the abort-on-drop behavior — from this point on,
        // we own the handles directly and will await them below.
        let event_watcher = event_watcher.into_inner();
        let init_trace = init_trace.into_inner();
        let test_stdout = test_stdout.into_inner();
        let test_stderr = test_stderr.into_inner();
        let kernel_log = kernel_log.into_inner();

        // ── Collect vsock / task output ──────────────────────────────
        // The vsock readers complete when the guest-side streams close
        // (test process exits → stdout/stderr close; n-it exits →
        // init_trace closes).
        let init_trace = join_or_fallback(init_trace, "init system trace").await;
        let test_stdout = join_or_fallback(test_stdout, "test stdout").await;
        let test_stderr = join_or_fallback(test_stderr, "test stderr").await;

        // The event watcher completes when the hypervisor emits a
        // terminal event (Shutdown / Panic) or the pipe closes.
        let (hypervisor_events, hypervisor_verdict) = match event_watcher.await {
            Ok(result) => result,
            Err(err) => {
                error!("hypervisor event watcher task failed: {err}");
                (Vec::new(), HypervisorVerdict::Failure)
            }
        };

        // ── Shut down ────────────────────────────────────────────────
        // Best-effort shutdown BEFORE waiting for the hypervisor process
        // to exit.  In the normal path the VM has already powered off
        // (n-it calls reboot(RB_POWER_OFF) or aborts), so these calls
        // will fail harmlessly.  But if the guest init hangs or the
        // shutdown path fails, these calls break the deadlock that would
        // otherwise occur when `collect_process_output` waits for the
        // hypervisor process to exit.
        if let Err(err) = client.lock().await.shutdown_vm().await as Result<(), _> {
            debug!("vm shutdown: {err}");
        }
        if let Err(err) = client.lock().await.shutdown_vmm().await as Result<(), _> {
            debug!("vmm shutdown: {err}");
        }

        let (hypervisor_exit_ok, hypervisor_stdout, hypervisor_stderr) =
            collect_process_output(hypervisor, "cloud-hypervisor").await;

        // The kernel serial socket closes when the hypervisor exits.
        let kernel_log = join_or_fallback(kernel_log, "kernel log").await;

        let (virtiofsd_exit_ok, virtiofsd_stdout, virtiofsd_stderr) =
            collect_process_output(virtiofsd, "virtiofsd").await;

        // ── Assemble result ──────────────────────────────────────────
        //
        // The Rust test harness (invoked with `--format=terse`) writes a
        // summary line to stdout:
        //
        //   test result: ok. 1 passed; 0 failed; …
        //   test result: FAILED. 0 passed; 1 failed; …
        //
        // We check for the failure marker so that a test-level failure is
        // not masked by a clean infrastructure shutdown.  This is the most
        // reliable signal available without modifying the init system to
        // forward the test process's exit code over a dedicated channel.
        let test_passed = !test_stdout.contains("test result: FAILED");

        VmTestOutput {
            success: test_passed
                && virtiofsd_exit_ok
                && hypervisor_verdict.is_success()
                && hypervisor_exit_ok,
            stdout: test_stdout,
            stderr: test_stderr,
            console: kernel_log,
            init_trace,
            hypervisor_stdout,
            hypervisor_stderr,
            virtiofsd_stdout,
            virtiofsd_stderr,
            hypervisor_events,
        }
    }
}

// ── run_in_vm ────────────────────────────────────────────────────────

/// Boots a cloud-hypervisor VM and runs the test function inside it.
///
/// This is the **container-tier** entry point, called from the code generated
/// by `#[in_vm]` when `IN_TEST_CONTAINER=YES`.  It:
///
/// 1. Resolves the test identity from the type parameter and `argv[0]`.
/// 2. Delegates to [`TestVm::launch`] to prepare and boot the VM.
/// 3. Delegates to [`TestVm::collect`] to wait for the test and gather output.
///
/// The type parameter `F` is used only to derive the test name via
/// [`std::any::type_name`]; the function itself is never called in this tier.
///
/// # Errors
///
/// Returns [`VmError`] if any part of the VM launch sequence fails.
/// Output collection is best-effort and never fails — see
/// [`TestVm::collect`].
pub async fn run_in_vm<F: FnOnce()>(_: F) -> Result<VmTestOutput, VmError> {
    // ── Resolve test identity ────────────────────────────────────────
    //
    // `type_name::<F>()` returns the fully-qualified path of the function
    // item type, e.g. `"my_crate::tests::my_test"`.  When `F` is a
    // reference to a function item (which can happen depending on how the
    // macro captures the function), the output is prefixed with `"&"`, so
    // we strip that.
    //
    // NOTE: `type_name` is explicitly documented as not stable across
    // compiler versions, but the `crate::path` format has been consistent
    // in practice and is the same mechanism the proc macro relies on.
    let type_name = std::any::type_name::<F>().trim_start_matches("&");
    let full_bin_path = std::env::args()
        .next()
        .ok_or(VmError::MissingArgv)?;
    let (_, bin_name) = full_bin_path
        .rsplit_once("/")
        .ok_or_else(|| VmError::InvalidBinaryPath {
            path: full_bin_path.clone(),
        })?;
    // type_name for a function item type always contains "::" because it
    // is fully qualified (e.g. "crate::module::function").  If this
    // invariant is violated, the Rust compiler changed its type_name
    // format in an incompatible way.
    let (_, test_name) = type_name
        .split_once("::")
        .unwrap_or_else(|| unreachable!(
            "std::any::type_name::<F>() did not contain '::': {type_name:?}"
        ));

    let params = TestVmParams {
        full_bin_path: &full_bin_path,
        bin_name,
        test_name,
    };

    let vm = TestVm::launch(&params).await?;
    Ok(vm.collect().await)
}