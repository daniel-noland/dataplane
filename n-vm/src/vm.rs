//! Cloud-hypervisor VM lifecycle management for the container tier.
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
//! This module handles launching virtiofsd, configuring and booting a
//! cloud-hypervisor VM, collecting output from all subsystems, and returning
//! a unified [`VmTestOutput`].
//!
//! Test process stdout and stderr are forwarded from the VM guest to the
//! container tier via dedicated [`VsockChannel`]s, giving the host clean
//! separation of the two channels.  The cloud-hypervisor virtio-console
//! (`hvc0`) is disabled -- all test output travels over vsock.
//!
//! # Lifecycle
//!
//! The [`TestVm`] struct owns every long-lived resource (child processes,
//! background tasks, API client) and exposes a two-phase API:
//!
//! 1. [`TestVm::launch`] -- prepares the environment (virtiofsd, vsock
//!    listeners, cloud-hypervisor) and boots the VM.
//! 2. [`TestVm::collect`] -- waits for the test to finish, gathers output
//!    from all subsystems, and performs a clean shutdown.
//!
//! The convenience function [`run_in_vm`] wraps both phases for the
//! `#[in_vm]` macro.

use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};
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
    KERNEL_CONSOLE_SOCKET_PATH, KERNEL_IMAGE_PATH, VHOST_VSOCK_SOCKET_PATH, VIRTIOFS_ROOT_TAG,
    VIRTIOFSD_BINARY_PATH, VIRTIOFSD_SOCKET_PATH, VM_GUEST_CID, VM_ROOT_SHARE_PATH, VM_RUN_DIR,
    VsockChannel,
};
use tokio::io::AsyncReadExt;
use tokio::task::JoinHandle;
use tracing::{debug, error, warn};

use crate::abort_on_drop::AbortOnDrop;
use crate::error::VmError;
use crate::hypervisor::{self, HypervisorVerdict};

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
const EVENT_MONITOR_FD: RawFd = 3;

/// Total guest memory in bytes (512 MiB).
const VM_MEMORY_BYTES: i64 = 512 * 1024 * 1024;

/// Hugepage size in bytes (2 MiB).
const VM_HUGEPAGE_BYTES: i64 = 2 * 1024 * 1024;

/// Number of 2 MiB hugepages to reserve on the kernel command line.
const VM_HUGEPAGE_COUNT: u32 = 16;

/// MTU for the management network interface (standard Ethernet).
const MGMT_MTU: i32 = 1500;

/// MTU for fabric-facing network interfaces (jumbo frames).
const FABRIC_MTU: i32 = 9500;

/// Virtio queue depth for the management network interface.
const MGMT_QUEUE_SIZE: i32 = 512;

/// Virtio queue depth for fabric-facing network interfaces.
const FABRIC_QUEUE_SIZE: i32 = 8192;

/// Virtio queue depth for the virtiofs filesystem device.
const VIRTIOFS_QUEUE_SIZE: i32 = 1024;

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

/// Parameters that vary per test invocation and feed into the VM
/// configuration.
///
/// Everything else in the [`VmConfig`] is an infrastructure default
/// derived from the module-level constants.  Call
/// [`build_vm_config`](Self::build_vm_config) to compose the full VM
/// configuration from focused sub-builders.
///
/// # Usage
///
/// ```ignore
/// let config = params.build_vm_config();
/// ```
pub struct TestVmParams<'a> {
    /// Full path to the test binary (e.g. `/path/to/deps/my_test-abc123`).
    pub full_bin_path: &'a Path,
    /// Short binary name (filename component only, e.g. `my_test-abc123`).
    pub bin_name: &'a str,
    /// Fully-qualified test name (e.g. `module::test_name`).
    pub test_name: &'a str,
}

impl<'a> TestVmParams<'a> {
    /// Builds the kernel payload configuration, including the kernel
    /// command line that passes the test binary path and name to the init
    /// system.
    fn build_payload_config(&self) -> PayloadConfig {
        PayloadConfig {
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
                 hugepages={VM_HUGEPAGE_COUNT} \
                 init={INIT_BINARY_PATH} \
                 -- {full_bin_path} {test_name} --exact --no-capture --format=terse",
                full_bin_path = self.full_bin_path.display(),
                test_name = self.test_name,
            )),
            ..Default::default()
        }
    }

    /// Builds the CPU topology: 6 vCPUs arranged as 3 dies x 1 core x 2
    /// threads.
    fn build_cpu_config() -> CpusConfig {
        CpusConfig {
            boot_vcpus: 6,
            max_vcpus: 6,
            topology: Some(CpuTopology {
                threads_per_core: Some(2),
                cores_per_die: Some(1),
                dies_per_package: Some(3),
                packages: Some(1),
            }),
            ..Default::default()
        }
    }

    /// Builds the memory configuration.
    fn build_memory_config() -> MemoryConfig {
        MemoryConfig {
            size: VM_MEMORY_BYTES,
            mergeable: Some(true),
            shared: Some(true),
            hugepages: Some(true),
            hugepage_size: Some(VM_HUGEPAGE_BYTES),
            thp: Some(true),
            ..Default::default()
        }
    }

    /// Builds the network interface configurations.
    ///
    /// Returns three interfaces:
    /// - **mgmt** -- management network on PCI segment 0 (1500 MTU).
    /// - **fabric1** / **fabric2** -- fabric-facing interfaces on PCI
    ///   segment 1 (9500 MTU jumbo frames).
    fn build_network_configs() -> Vec<NetConfig> {
        vec![
            NetConfig {
                tap: Some("mgmt".into()),
                ip: Some("fe80::ffff:1".into()),
                mask: Some("ffff:ffff:ffff:ffff::".into()),
                mac: Some("02:DE:AD:BE:EF:01".into()),
                mtu: Some(MGMT_MTU),
                id: Some("mgmt".into()),
                pci_segment: Some(0),
                queue_size: Some(MGMT_QUEUE_SIZE),
                ..Default::default()
            },
            NetConfig {
                tap: Some("fabric1".into()),
                ip: Some("fe80::1".into()),
                mask: Some("ffff:ffff:ffff:ffff::".into()),
                mac: Some("02:CA:FE:BA:BE:01".into()),
                mtu: Some(FABRIC_MTU),
                id: Some("fabric1".into()),
                pci_segment: Some(1),
                queue_size: Some(FABRIC_QUEUE_SIZE),
                ..Default::default()
            },
            NetConfig {
                tap: Some("fabric2".into()),
                ip: Some("fe80::2".into()),
                mask: Some("ffff:ffff:ffff:ffff::".into()),
                mac: Some("02:CA:FE:BA:BE:02".into()),
                mtu: Some(FABRIC_MTU),
                id: Some("fabric2".into()),
                pci_segment: Some(1),
                queue_size: Some(FABRIC_QUEUE_SIZE),
                ..Default::default()
            },
        ]
    }

    /// Builds the virtiofs filesystem configuration for sharing the
    /// container filesystem into the VM.
    fn build_fs_config() -> Vec<FsConfig> {
        vec![FsConfig {
            tag: VIRTIOFS_ROOT_TAG.into(),
            socket: VIRTIOFSD_SOCKET_PATH.into(),
            num_queues: 1,
            queue_size: VIRTIOFS_QUEUE_SIZE,
            id: Some(VIRTIOFS_ROOT_TAG.into()),
            ..Default::default()
        }]
    }

    /// Builds the platform metadata configuration, embedding the test
    /// binary name and test name in OEM strings for identification.
    fn build_platform_config(&self) -> PlatformConfig {
        PlatformConfig {
            serial_number: Some("dataplane-test".into()),
            uuid: Some("dff9c8dd-492d-4148-a007-7931f94db852".into()), // arbitrary uuid4
            oem_strings: Some(vec![
                format!("exe={}", self.bin_name),
                format!("test={}", self.test_name),
            ]),
            num_pci_segments: Some(2),
            ..Default::default()
        }
    }

    /// Builds the cloud-hypervisor [`VmConfig`] for a test run.
    ///
    /// This method composes the VM configuration from focused sub-builders,
    /// each responsible for a single aspect of the configuration (payload,
    /// CPU, memory, network, filesystem, platform).  The sub-builders can
    /// be tested and evolved independently.
    ///
    /// The virtio-console is disabled (`Mode::Off`) because test
    /// stdout/stderr are forwarded via dedicated [`VsockChannel`]s instead.
    fn build_vm_config(&self) -> VmConfig {
        VmConfig {
            payload: self.build_payload_config(),
            vsock: Some(VsockConfig {
                cid: VM_GUEST_CID.as_raw() as _,
                socket: VHOST_VSOCK_SOCKET_PATH.into(),
                pci_segment: Some(0),
                ..Default::default()
            }),
            cpus: Some(Self::build_cpu_config()),
            memory: Some(Self::build_memory_config()),
            net: Some(Self::build_network_configs()),
            fs: Some(Self::build_fs_config()),
            // The virtio-console is disabled: test stdout/stderr travel
            // over dedicated VsockChannels (TEST_STDOUT / TEST_STDERR).
            console: Some(ConsoleConfig::new(Mode::Off)),
            serial: Some(ConsoleConfig {
                mode: Mode::Socket,
                socket: Some(KERNEL_CONSOLE_SOCKET_PATH.into()),
                ..Default::default()
            }),
            iommu: Some(false),
            watchdog: Some(true),
            platform: Some(self.build_platform_config()),
            pvpanic: Some(true),
            landlock_enable: Some(true),
            landlock_rules: Some(vec![LandlockConfig {
                path: VM_RUN_DIR.into(),
                access: "rw".into(),
            }]),
            ..Default::default()
        }
    }
}

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
    /// Captured stdout and stderr from the test process (via vsock).
    pub test: ProcessOutput,
    /// Kernel serial console output (from the guest's `ttyS0`).
    pub console: String,
    /// Tracing output from the `n-it` init system, streamed via vsock.
    pub init_trace: String,
    /// Captured stdout, stderr, and exit status of the cloud-hypervisor
    /// process itself.
    pub hypervisor: ProcessOutput,
    /// Cloud-hypervisor lifecycle events collected during the VM's lifetime.
    pub hypervisor_events: Vec<hypervisor::Event>,
    /// Captured stdout, stderr, and exit status of the virtiofsd process.
    pub virtiofsd: ProcessOutput,
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
        self.hypervisor.fmt_sections(f, "cloud-hypervisor")?;
        self.virtiofsd.fmt_sections(f, "virtiofsd")?;
        writeln!(f, "--------------- linux console ---------------")?;
        writeln!(f, "{}", self.console)?;
        writeln!(f, "--------------- init system ---------------")?;
        writeln!(f, "{}", self.init_trace)?;
        self.test.fmt_sections(f, "test")?;
        Ok(())
    }
}

/// Owns all long-lived resources for a running test VM.
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
    /// Binds a Unix listener for the given [`VsockChannel`], then spawns a
    /// task that accepts a single connection and reads it to EOF.
    ///
    /// This pattern is shared by the init-system tracing channel, test
    /// stdout, and test stderr -- all of which are vsock streams that the
    /// VM guest connects to via `vhost_vsock`.
    ///
    /// The listener must be bound *before* the VM boots so that the
    /// guest-side `vsock::VsockStream::connect()` succeeds immediately.
    fn spawn_vsock_reader(channel: &VsockChannel) -> Result<AbortOnDrop<String>, VmError> {
        let path = channel.listener_path();
        let label = channel.label;
        let listen =
            tokio::net::UnixListener::bind(&path).map_err(|source| VmError::VsockBind {
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

    /// Creates the event-monitor pipe, verifies `/dev/kvm`, spawns the
    /// cloud-hypervisor binary, and waits for the API socket to appear.
    ///
    /// Returns the child process handle and the event-monitor pipe
    /// receiver (which is consumed by [`hypervisor::watch`]).
    async fn spawn_hypervisor()
    -> Result<(tokio::process::Child, tokio::net::unix::pipe::Receiver), VmError> {
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

    /// Spawns a background task that connects to the kernel serial console
    /// socket and reads it to EOF.
    ///
    /// The console socket is created by cloud-hypervisor after the VM
    /// boots, so the task polls for its existence before attempting to
    /// connect.
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
    /// This method orchestrates five focused phases, each delegated to an
    /// associated function on this type:
    ///
    /// 1. [`launch_virtiofsd`](Self::launch_virtiofsd) -- share the
    ///    container filesystem into the VM.
    /// 2. [`spawn_vsock_reader`](Self::spawn_vsock_reader) -- bind vsock
    ///    listeners for all channels.
    /// 3. [`spawn_hypervisor`](Self::spawn_hypervisor) -- create the event
    ///    pipe, verify `/dev/kvm`, spawn cloud-hypervisor, and wait for the
    ///    API socket.
    /// 4. Create and boot the VM via the hypervisor REST API.
    /// 5. [`spawn_kernel_log_reader`](Self::spawn_kernel_log_reader) --
    ///    start collecting kernel console output.
    ///
    /// All background tasks are wrapped in [`AbortOnDrop`], so if any phase
    /// fails (or the method panics), previously spawned tasks are
    /// automatically aborted when their handles drop.  Child processes use
    /// `kill_on_drop(true)` for the same guarantee.
    pub async fn launch(params: &TestVmParams<'_>) -> Result<Self, VmError> {
        let virtiofsd = Self::launch_virtiofsd(VM_ROOT_SHARE_PATH).await?;
        // All listeners must be bound *before* the VM boots so that the
        // guest-side vsock connections succeed immediately.
        let init_trace = Self::spawn_vsock_reader(&VsockChannel::INIT_TRACE)?;
        let test_stdout = Self::spawn_vsock_reader(&VsockChannel::TEST_STDOUT)?;
        let test_stderr = Self::spawn_vsock_reader(&VsockChannel::TEST_STDERR)?;

        let (hypervisor, event_receiver) = Self::spawn_hypervisor().await?;

        let config = params.build_vm_config();

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

        let kernel_log = Self::spawn_kernel_log_reader();

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
    /// `"!!!...UNAVAILABLE...!!!"`) rather than propagated as errors, because
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
        // terminal event (Shutdown / Panic) or the pipe closes.
        let (hypervisor_events, hypervisor_verdict) = match event_watcher.await {
            Ok(result) => result,
            Err(err) => {
                error!("hypervisor event watcher task failed: {err}");
                (Vec::new(), HypervisorVerdict::Failure)
            }
        };

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

        let hypervisor_output = ProcessOutput::from_child(hypervisor, "cloud-hypervisor").await;

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
/// Output collection is best-effort and never fails -- see
/// [`TestVm::collect`].
pub async fn run_in_vm<F: FnOnce()>(_: F) -> Result<VmTestOutput, VmError> {
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

    let vm = TestVm::launch(&params).await?;
    Ok(vm.collect().await)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a representative [`TestVmParams`] for use in config builder
    /// tests.  The values are arbitrary but realistic.
    fn sample_params() -> TestVmParams<'static> {
        TestVmParams {
            full_bin_path: Path::new("/target/debug/deps/my_test-abc123"),
            bin_name: "my_test-abc123",
            test_name: "tests::my_test",
        }
    }

    #[test]
    fn payload_config_uses_kernel_image_path() {
        let params = sample_params();
        let payload = params.build_payload_config();
        assert_eq!(payload.kernel.as_deref(), Some(KERNEL_IMAGE_PATH));
    }

    #[test]
    fn payload_config_embeds_test_binary_in_cmdline() {
        let params = sample_params();
        let payload = params.build_payload_config();
        let cmdline = payload.cmdline.as_deref().expect("cmdline should be set");
        assert!(
            cmdline.contains("/target/debug/deps/my_test-abc123"),
            "cmdline should contain the full binary path: {cmdline}",
        );
    }

    #[test]
    fn payload_config_embeds_test_name_in_cmdline() {
        let params = sample_params();
        let payload = params.build_payload_config();
        let cmdline = payload.cmdline.as_deref().expect("cmdline should be set");
        assert!(
            cmdline.contains("tests::my_test"),
            "cmdline should contain the test name: {cmdline}",
        );
    }

    #[test]
    fn payload_config_sets_init_binary() {
        let params = sample_params();
        let payload = params.build_payload_config();
        let cmdline = payload.cmdline.as_deref().expect("cmdline should be set");
        assert!(
            cmdline.contains(&format!("init={INIT_BINARY_PATH}")),
            "cmdline should specify the init binary: {cmdline}",
        );
    }

    #[test]
    fn payload_config_enables_hugepages_on_cmdline() {
        let params = sample_params();
        let payload = params.build_payload_config();
        let cmdline = payload.cmdline.as_deref().expect("cmdline should be set");
        assert!(
            cmdline.contains(&format!("hugepages={VM_HUGEPAGE_COUNT}")),
            "cmdline should configure hugepage count: {cmdline}",
        );
        assert!(
            cmdline.contains("hugepagesz=2M"),
            "cmdline should configure hugepage size: {cmdline}",
        );
    }

    #[test]
    fn payload_config_passes_exact_flag_to_test_harness() {
        let params = sample_params();
        let payload = params.build_payload_config();
        let cmdline = payload.cmdline.as_deref().expect("cmdline should be set");
        assert!(
            cmdline.contains("--exact"),
            "cmdline should pass --exact to the test harness: {cmdline}",
        );
        assert!(
            cmdline.contains("--no-capture"),
            "cmdline should pass --no-capture to the test harness: {cmdline}",
        );
    }

    #[test]
    fn cpu_config_has_six_vcpus() {
        let cpus = TestVmParams::build_cpu_config();
        assert_eq!(cpus.boot_vcpus, 6);
        assert_eq!(cpus.max_vcpus, 6);
    }

    #[test]
    fn cpu_topology_is_three_dies_by_one_core_by_two_threads() {
        let cpus = TestVmParams::build_cpu_config();
        let topo = cpus.topology.expect("topology should be set");
        assert_eq!(topo.threads_per_core, Some(2));
        assert_eq!(topo.cores_per_die, Some(1));
        assert_eq!(topo.dies_per_package, Some(3));
        assert_eq!(topo.packages, Some(1));
        // Sanity: product of topology should equal boot_vcpus.
        let total = topo.threads_per_core.unwrap()
            * topo.cores_per_die.unwrap()
            * topo.dies_per_package.unwrap()
            * topo.packages.unwrap();
        assert_eq!(
            total, cpus.boot_vcpus,
            "topology product ({total}) should match boot_vcpus ({})",
            cpus.boot_vcpus,
        );
    }

    #[test]
    fn memory_config_has_expected_size() {
        let mem = TestVmParams::build_memory_config();
        assert_eq!(mem.size, VM_MEMORY_BYTES);
    }

    #[test]
    fn memory_config_enables_hugepages_and_sharing() {
        let mem = TestVmParams::build_memory_config();
        assert_eq!(mem.hugepages, Some(true));
        assert_eq!(mem.hugepage_size, Some(VM_HUGEPAGE_BYTES));
        assert_eq!(
            mem.shared,
            Some(true),
            "shared memory is required for virtiofs"
        );
        assert_eq!(mem.mergeable, Some(true));
        assert_eq!(mem.thp, Some(true));
    }

    #[test]
    fn network_config_has_three_interfaces() {
        let nets = TestVmParams::build_network_configs();
        assert_eq!(nets.len(), 3);
    }

    #[test]
    fn mgmt_interface_is_on_pci_segment_zero_with_standard_mtu() {
        let nets = TestVmParams::build_network_configs();
        let mgmt = nets
            .iter()
            .find(|n| n.id.as_deref() == Some("mgmt"))
            .expect("should have a 'mgmt' interface");
        assert_eq!(mgmt.pci_segment, Some(0));
        assert_eq!(mgmt.mtu, Some(MGMT_MTU));
        assert_eq!(mgmt.queue_size, Some(MGMT_QUEUE_SIZE));
    }

    #[test]
    fn fabric_interfaces_are_on_pci_segment_one_with_jumbo_mtu() {
        let nets = TestVmParams::build_network_configs();
        for name in &["fabric1", "fabric2"] {
            let iface = nets
                .iter()
                .find(|n| n.id.as_deref() == Some(*name))
                .unwrap_or_else(|| panic!("should have a '{name}' interface"));
            assert_eq!(iface.pci_segment, Some(1), "{name} PCI segment");
            assert_eq!(iface.mtu, Some(FABRIC_MTU), "{name} MTU");
            assert_eq!(
                iface.queue_size,
                Some(FABRIC_QUEUE_SIZE),
                "{name} queue size"
            );
        }
    }

    #[test]
    fn all_interfaces_have_unique_mac_addresses() {
        let nets = TestVmParams::build_network_configs();
        let macs: Vec<_> = nets.iter().filter_map(|n| n.mac.as_deref()).collect();
        assert_eq!(macs.len(), 3, "all interfaces should have MAC addresses");
        let mut deduped = macs.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(
            macs.len(),
            deduped.len(),
            "all MAC addresses should be unique"
        );
    }

    #[test]
    fn all_interfaces_have_unique_tap_names() {
        let nets = TestVmParams::build_network_configs();
        let taps: Vec<_> = nets.iter().filter_map(|n| n.tap.as_deref()).collect();
        assert_eq!(taps.len(), 3, "all interfaces should have tap names");
        let mut deduped = taps.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(taps.len(), deduped.len(), "all tap names should be unique");
    }

    #[test]
    fn fs_config_uses_virtiofs_root_tag_and_socket() {
        let fs = TestVmParams::build_fs_config();
        assert_eq!(fs.len(), 1);
        let entry = &fs[0];
        assert_eq!(entry.tag, VIRTIOFS_ROOT_TAG);
        assert_eq!(entry.socket, VIRTIOFSD_SOCKET_PATH);
        assert_eq!(entry.queue_size, VIRTIOFS_QUEUE_SIZE);
    }

    #[test]
    fn platform_config_embeds_binary_and_test_name_in_oem_strings() {
        let params = sample_params();
        let platform = params.build_platform_config();
        let oem = platform.oem_strings.expect("oem_strings should be set");
        assert!(
            oem.iter().any(|s| s == "exe=my_test-abc123"),
            "OEM strings should contain the binary name: {oem:?}",
        );
        assert!(
            oem.iter().any(|s| s == "test=tests::my_test"),
            "OEM strings should contain the test name: {oem:?}",
        );
    }

    #[test]
    fn platform_config_has_two_pci_segments() {
        let params = sample_params();
        let platform = params.build_platform_config();
        assert_eq!(platform.num_pci_segments, Some(2));
    }

    #[test]
    fn vm_config_disables_virtio_console() {
        let params = sample_params();
        let config = params.build_vm_config();
        let console = config.console.expect("console should be set");
        assert_eq!(console.mode, Mode::Off);
    }

    #[test]
    fn vm_config_serial_uses_socket_mode() {
        let params = sample_params();
        let config = params.build_vm_config();
        let serial = config.serial.expect("serial should be set");
        assert_eq!(serial.mode, Mode::Socket);
        assert_eq!(serial.socket.as_deref(), Some(KERNEL_CONSOLE_SOCKET_PATH),);
    }

    #[test]
    fn vm_config_vsock_uses_guest_cid() {
        let params = sample_params();
        let config = params.build_vm_config();
        let vsock = config.vsock.expect("vsock should be set");
        assert_eq!(vsock.cid, VM_GUEST_CID.as_raw() as i64);
        assert_eq!(vsock.socket, VHOST_VSOCK_SOCKET_PATH);
    }

    #[test]
    fn vm_config_enables_safety_features() {
        let params = sample_params();
        let config = params.build_vm_config();
        assert_eq!(config.watchdog, Some(true), "watchdog should be enabled");
        assert_eq!(config.pvpanic, Some(true), "pvpanic should be enabled");
        assert_eq!(
            config.iommu,
            Some(false),
            "iommu should be disabled at VM level"
        );
    }

    #[test]
    fn vm_config_enables_landlock_with_vm_run_dir() {
        let params = sample_params();
        let config = params.build_vm_config();
        assert_eq!(config.landlock_enable, Some(true));
        let rules = config.landlock_rules.expect("landlock_rules should be set");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].path, VM_RUN_DIR);
        assert_eq!(rules[0].access, "rw");
    }
}
