// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! QEMU [`HypervisorBackend`] implementation.
//!
//! This module encapsulates all
//! [QEMU](https://www.qemu.org/)-specific concerns:
//!
//! - **VM configuration** -- translating [`TestVmParams`] into QEMU
//!   command-line arguments via focused sub-builders.
//! - **Process spawning** -- launching `qemu-system-x86_64` with the
//!   assembled arguments; QEMU boots the VM immediately on process start
//!   (unlike cloud-hypervisor, which separates VMM startup from VM boot).
//! - **Lifecycle control** -- connecting to the QMP (QEMU Machine
//!   Protocol) socket for shutdown commands.
//! - **Event monitoring** -- consuming async QMP events (`SHUTDOWN`,
//!   `GUEST_PANICKED`, etc.) and producing a [`HypervisorVerdict`].
//!
//! Nothing in this module is used by the generic [`TestVm`](crate::vm::TestVm)
//! machinery except through the [`HypervisorBackend`] trait.
//!
//! # Architecture differences from cloud-hypervisor
//!
//! | Concern    | cloud-hypervisor                   | QEMU                            |
//! |------------|------------------------------------|---------------------------------|
//! | Boot model | `create_vm` + `boot_vm` REST       | Boots on process start          |
//! | Control    | REST API over Unix socket          | QMP (JSON-RPC) over Unix socket |
//! | Events     | `--event-monitor fd=N` pipe        | QMP async events                |
//! | Shutdown   | `shutdown_vm()` + `shutdown_vmm()` | `system_powerdown` + `quit`     |
//! | Config     | JSON `VmConfig` body               | Command-line arguments          |
//!
//! # vsock bridging
//!
//! Cloud-hypervisor has a built-in vhost-user-vsock implementation that
//! transparently maps guest vsock connections to host-side Unix sockets
//! at `$VHOST_SOCKET_$PORT`.  Its
//! [`spawn_vsock_reader`](crate::backend::HypervisorBackend::spawn_vsock_reader)
//! implementation binds [`UnixListener`](tokio::net::UnixListener)s at
//! those paths.
//!
//! QEMU's `vhost-vsock-pci` device uses the kernel's vhost-vsock module
//! instead, which surfaces guest connections as `AF_VSOCK` sockets on
//! the host.  This backend's
//! [`spawn_vsock_reader`](Qemu::spawn_vsock_reader) implementation uses
//! [`tokio_vsock::VsockListener`] bound to `VMADDR_CID_ANY` on the
//! channel's port, so the kernel routes guest vsock connections directly
//! to the listener without any intermediate Unix socket mapping.
//!
//! The [`qmp`] submodule contains the QMP protocol client and wire types.

pub mod error;
pub(crate) mod qmp;

pub use self::error::QemuError;

use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use n_vm_protocol::{
    HYPERVISOR_API_SOCKET_PATH, INIT_BINARY_PATH, KERNEL_CONSOLE_SOCKET_PATH, KERNEL_IMAGE_PATH,
    QEMU_BINARY_PATH, VIRTIOFS_ROOT_TAG, VIRTIOFSD_SOCKET_PATH, VM_GUEST_CID, VsockChannel,
};
use tokio::io::AsyncReadExt;
use tracing::{debug, error, warn};

use crate::abort_on_drop::AbortOnDrop;
use crate::backend::{HypervisorBackend, HypervisorVerdict, LaunchedHypervisor};
use crate::error::VmError;
use crate::vm::{TestVmParams, check_kvm_accessible, wait_for_socket};

use self::qmp::{EventDisplay, QmpCommandName, QmpConnection, QmpEventStream, QmpWriter};

// ── Constants ────────────────────────────────────────────────────────
//
// These mirror the constants in the cloud_hypervisor module.  Both
// backends run the same test environment, so the VM configuration must
// match.  A shared configuration module would eliminate the duplication;
// for now, keeping them backend-local avoids coupling the two modules.

/// Total guest memory in MiB.
///
/// Matches the cloud-hypervisor backend's `VM_MEMORY_BYTES / 1 MiB`.
const VM_MEMORY_MIB: u32 = 512;

/// Number of 2 MiB hugepages to reserve on the kernel command line.
const VM_HUGEPAGE_COUNT: u32 = 16;

/// Number of vCPUs.
const VM_VCPUS: u32 = 6;

/// Threads per core in the CPU topology.
const VM_THREADS_PER_CORE: u32 = 2;

/// Cores per die in the CPU topology.
const VM_CORES_PER_DIE: u32 = 1;

/// Dies per socket in the CPU topology.
const VM_DIES_PER_SOCKET: u32 = 3;

/// Sockets in the CPU topology.
const VM_SOCKETS: u32 = 1;

/// Virtio queue depth for the virtiofs filesystem device.
const VIRTIOFS_QUEUE_SIZE: u32 = 1024;

/// Initial buffer capacity for vsock reader tasks.
const VSOCK_READER_CAPACITY: usize = 32_768;

/// Duration to continue draining QMP events after a guest panic is
/// detected.
///
/// This matches the cloud-hypervisor backend's `POST_PANIC_DRAIN_TIMEOUT`.
const POST_PANIC_DRAIN_TIMEOUT: Duration = Duration::from_millis(500);

// ── Network interface descriptors ────────────────────────────────────

/// Describes a network interface for QEMU CLI argument generation.
struct NetIface {
    /// Unique identifier used in netdev and device arguments.
    id: &'static str,
    /// TAP device name on the host.
    tap: &'static str,
    /// MAC address in `XX:XX:XX:XX:XX:XX` format.
    mac: &'static str,
}

/// The management network interface (standard Ethernet MTU).
const IFACE_MGMT: NetIface = NetIface {
    id: "mgmt",
    tap: "mgmt",
    mac: "02:DE:AD:BE:EF:01",
};

/// First fabric-facing network interface (jumbo MTU).
const IFACE_FABRIC1: NetIface = NetIface {
    id: "fabric1",
    tap: "fabric1",
    mac: "02:CA:FE:BA:BE:01",
};

/// Second fabric-facing network interface (jumbo MTU).
const IFACE_FABRIC2: NetIface = NetIface {
    id: "fabric2",
    tap: "fabric2",
    mac: "02:CA:FE:BA:BE:02",
};

// ── Public types ─────────────────────────────────────────────────────

/// QEMU [`HypervisorBackend`] implementation.
///
/// Launches a `qemu-system-x86_64` process that boots the VM immediately,
/// monitors lifecycle events through the QMP socket, and performs shutdown
/// via QMP commands.
#[derive(Debug)]
pub struct Qemu;

/// Lifecycle controller for a running QEMU instance.
///
/// Wraps a [`QmpWriter`] behind a mutex for interior mutability, since
/// the [`HypervisorBackend::shutdown`] method takes `&Self::Controller`.
pub struct QemuController {
    writer: Arc<tokio::sync::Mutex<QmpWriter>>,
}

/// Collected QMP event log from a QEMU VM's lifetime.
///
/// This newtype wraps the raw event vector so that the generic
/// [`VmTestOutput`](crate::vm::VmTestOutput) can store and display
/// backend-specific event data through the [`Display`](std::fmt::Display)
/// bound on [`HypervisorBackend::EventLog`].
///
/// The [`Display`](std::fmt::Display) implementation produces one line per
/// event in a human-readable format suitable for test failure diagnostics.
#[derive(Debug, Default)]
pub struct QemuEventLog(pub Vec<qapi_qmp::Event>);

impl std::fmt::Display for QemuEventLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for event in &self.0 {
            let ts = event.timestamp();
            write!(f, "[{ts:?}] ")?;
            writeln!(f, "{}", EventDisplay(event))?;
        }
        Ok(())
    }
}

// ── Error conversion ─────────────────────────────────────────────────

impl From<QemuError> for VmError {
    fn from(err: QemuError) -> Self {
        VmError::Backend(Box::new(err))
    }
}

// ── HypervisorBackend ────────────────────────────────────────────────

impl HypervisorBackend for Qemu {
    const NAME: &str = "qemu";

    type EventLog = QemuEventLog;
    type Controller = QemuController;

    async fn launch(params: &TestVmParams<'_>) -> Result<LaunchedHypervisor<Self>, VmError> {
        let (child, qmp_conn) = spawn_qemu_process(params).await?;

        let (writer, event_stream) = qmp_conn.into_split();

        let event_watcher = AbortOnDrop::spawn(async {
            let (events, verdict) = watch_events(event_stream).await;
            (QemuEventLog(events), verdict)
        });

        Ok(LaunchedHypervisor {
            child,
            event_watcher,
            controller: QemuController {
                writer: Arc::new(tokio::sync::Mutex::new(writer)),
            },
        })
    }

    async fn shutdown(controller: &Self::Controller) {
        // In the normal path the VM has already powered off (n-it calls
        // reboot(RB_POWER_OFF) or aborts), and QEMU is paused due to
        // -no-shutdown.  These commands break that pause and exit QEMU.
        //
        // If the guest init hangs, `system_powerdown` sends an ACPI power
        // button event, and `quit` forcefully terminates the VMM.
        let mut writer = controller.writer.lock().await;
        writer
            .send_command_fire_and_forget(QmpCommandName::SystemPowerdown)
            .await;
        writer
            .send_command_fire_and_forget(QmpCommandName::Quit)
            .await;
    }

    fn spawn_vsock_reader(channel: &VsockChannel) -> Result<AbortOnDrop<String>, VmError> {
        let port = channel.port.as_raw();
        let label = channel.label;

        // Bind an AF_VSOCK listener on VMADDR_CID_ANY so the kernel's
        // vhost-vsock module will route guest connections to us.
        let addr = tokio_vsock::VsockAddr::new(tokio_vsock::VMADDR_CID_ANY, port);
        let listener =
            tokio_vsock::VsockListener::bind(addr).map_err(|source| VmError::VsockBind {
                label,
                path: format!("vsock://any:{port}").into(),
                source,
            })?;

        Ok(AbortOnDrop::spawn(async move {
            let mut buf = Vec::with_capacity(VSOCK_READER_CAPACITY);
            let mut connection = match listener.accept().await {
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
}

// ── Event monitoring ─────────────────────────────────────────────────

/// Consumes the QMP event stream and returns the collected events along
/// with a [`HypervisorVerdict`].
///
/// Event collection terminates when:
/// - A `SHUTDOWN` event is received (normal completion).
/// - A `GUEST_PANICKED` event is received (remaining events are drained
///   for up to [`POST_PANIC_DRAIN_TIMEOUT`]).
/// - The stream ends (socket closed / QEMU exited).
///
/// The verdict is computed by [`compute_verdict`] from the collected
/// events and a flag tracking whether any stream-level errors occurred.
async fn watch_events(mut stream: QmpEventStream) -> (Vec<qapi_qmp::Event>, HypervisorVerdict) {
    let mut log = Vec::with_capacity(16);
    let mut had_errors = false;

    loop {
        match stream.next_event().await {
            Ok(Some(event)) => {
                let is_shutdown = matches!(event, qapi_qmp::Event::SHUTDOWN { .. });
                let is_panic = matches!(event, qapi_qmp::Event::GUEST_PANICKED { .. });
                log.push(event);

                if is_shutdown || is_panic {
                    if is_panic {
                        drain_after_panic(&mut stream, &mut log).await;
                    }
                    break;
                }
            }
            Ok(None) => {
                // Stream closed -- QEMU exited.
                break;
            }
            Err(err) => {
                warn!("QMP event stream error (marking as failure): {err:#?}");
                had_errors = true;
            }
        }
    }

    let verdict = compute_verdict(&log, had_errors);
    (log, verdict)
}

/// Drains remaining QMP events for up to [`POST_PANIC_DRAIN_TIMEOUT`]
/// after a guest panic, appending them to `log`.
///
/// This gives QEMU time to emit subsequent events (e.g. `SHUTDOWN`) that
/// aid diagnosis.
async fn drain_after_panic(stream: &mut QmpEventStream, log: &mut Vec<qapi_qmp::Event>) {
    let deadline = tokio::time::sleep(POST_PANIC_DRAIN_TIMEOUT);
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            result = stream.next_event() => {
                match result {
                    Ok(Some(event)) => log.push(event),
                    Ok(None) => break,
                    Err(err) => {
                        warn!("QMP event error during post-panic drain: {err:#?}");
                    }
                }
            }
            () = &mut deadline => break,
        }
    }
}

/// Computes the [`HypervisorVerdict`] from collected QMP events and a
/// flag indicating whether any stream-level errors occurred.
///
/// This is a **pure function** extracted from [`watch_events`] so that
/// verdict logic can be unit-tested with hand-crafted event sequences
/// without needing a socket or tokio runtime.
///
/// The verdict is [`CleanShutdown`](HypervisorVerdict::CleanShutdown)
/// only if **all** of the following hold:
///
/// 1. A `SHUTDOWN` event was received.
/// 2. No `GUEST_PANICKED` event preceded the shutdown in the event log.
/// 3. No stream-level errors occurred (indicated by `had_stream_errors`).
///
/// Otherwise the verdict is [`Failure`](HypervisorVerdict::Failure).
pub fn compute_verdict(events: &[qapi_qmp::Event], had_stream_errors: bool) -> HypervisorVerdict {
    let mut tainted = had_stream_errors;

    for event in events {
        match event {
            qapi_qmp::Event::SHUTDOWN { .. } => {
                return if tainted {
                    HypervisorVerdict::Failure
                } else {
                    HypervisorVerdict::CleanShutdown
                };
            }
            qapi_qmp::Event::GUEST_PANICKED { .. } => {
                tainted = true;
            }
            _ => {}
        }
    }

    // Stream ended without a SHUTDOWN event.
    HypervisorVerdict::Failure
}

// ── Process spawning ─────────────────────────────────────────────────

/// Verifies KVM accessibility, spawns the QEMU process, waits for the
/// QMP socket, and establishes the QMP connection.
///
/// QEMU boots the VM immediately on process start (no separate
/// `create_vm` / `boot_vm` calls), so by the time the QMP connection is
/// established the VM is either running or has already failed to boot.
async fn spawn_qemu_process(
    params: &TestVmParams<'_>,
) -> Result<(tokio::process::Child, QmpConnection), VmError> {
    check_kvm_accessible().await?;

    let args = build_qemu_args(params);

    debug!("spawning QEMU: {} {}", QEMU_BINARY_PATH, args.join(" "));

    let child = tokio::process::Command::new(QEMU_BINARY_PATH)
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(VmError::HypervisorSpawn)?;

    // Wait for QEMU to create the QMP socket, then connect and negotiate.
    wait_for_socket(HYPERVISOR_API_SOCKET_PATH).await?;
    let qmp = QmpConnection::connect(HYPERVISOR_API_SOCKET_PATH).await?;

    Ok((child, qmp))
}

// ── CLI argument builders ────────────────────────────────────────────
//
// Each builder is a focused function responsible for a single aspect of
// the QEMU command line.  They can be tested and evolved independently;
// `build_qemu_args` composes them into the final argument vector.
//
// Arguments are pushed onto a `Vec<String>` rather than returned, so
// callers can compose multiple builders without intermediate allocation.

/// Builds the complete QEMU argument vector for a test run.
fn build_qemu_args(params: &TestVmParams<'_>) -> Vec<String> {
    let mut args = Vec::with_capacity(64);
    push_machine_args(&mut args);
    push_cpu_args(&mut args);
    push_memory_args(&mut args);
    push_kernel_args(&mut args, params);
    push_fs_args(&mut args);
    push_vsock_args(&mut args);
    push_network_args(&mut args);
    push_serial_args(&mut args);
    push_qmp_args(&mut args);
    push_platform_args(&mut args, params);
    push_misc_args(&mut args);
    args
}

/// Machine type and acceleration.
fn push_machine_args(args: &mut Vec<String>) {
    args.extend([
        "-enable-kvm".into(),
        "-machine".into(),
        "q35,accel=kvm".into(),
        "-cpu".into(),
        "host".into(),
    ]);
}

/// CPU count and topology.
///
/// Matches the cloud-hypervisor backend: 6 vCPUs arranged as
/// 1 socket × 3 dies × 1 core × 2 threads.
fn push_cpu_args(args: &mut Vec<String>) {
    args.extend([
        "-smp".into(),
        format!(
            "{VM_VCPUS},sockets={VM_SOCKETS},dies={VM_DIES_PER_SOCKET},\
             cores={VM_CORES_PER_DIE},threads={VM_THREADS_PER_CORE}"
        ),
    ]);
}

/// Memory configuration with hugepage backing and sharing.
///
/// Uses a `memory-backend-file` object backed by `/dev/hugepages` with
/// `share=on` (required for virtiofs / vhost-user-fs-pci) and
/// `prealloc=on` (ensures hugepages are allocated at VM start rather
/// than on first access).
///
/// The `-numa node,memdev=mem0` argument assigns the memory backend to
/// a NUMA node, which is how QEMU associates a memory backend with the
/// guest's address space.
fn push_memory_args(args: &mut Vec<String>) {
    args.extend([
        "-object".into(),
        format!(
            "memory-backend-file,id=mem0,size={VM_MEMORY_MIB}M,\
             mem-path=/dev/hugepages,share=on,prealloc=on"
        ),
        "-numa".into(),
        "node,memdev=mem0".into(),
    ]);
}

/// Kernel image and command line.
///
/// The kernel command line passes the test binary path and name to the
/// init system, matching the cloud-hypervisor backend exactly.
fn push_kernel_args(args: &mut Vec<String>, params: &TestVmParams<'_>) {
    let cmdline = format!(
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
        full_bin_path = params.full_bin_path.display(),
        test_name = params.test_name,
    );

    args.extend([
        "-kernel".into(),
        KERNEL_IMAGE_PATH.into(),
        "-append".into(),
        cmdline,
    ]);
}

/// Virtiofs filesystem device for sharing the container filesystem.
///
/// Uses `vhost-user-fs-pci` with a chardev pointing at the virtiofsd
/// socket, matching the cloud-hypervisor backend's filesystem
/// configuration.
fn push_fs_args(args: &mut Vec<String>) {
    args.extend([
        "-chardev".into(),
        format!("socket,id=virtiofs0,path={VIRTIOFSD_SOCKET_PATH}"),
        "-device".into(),
        format!(
            "vhost-user-fs-pci,queue-size={VIRTIOFS_QUEUE_SIZE},\
             chardev=virtiofs0,tag={VIRTIOFS_ROOT_TAG}"
        ),
    ]);
}

/// Vsock device for guest-to-host communication.
///
/// Uses `vhost-vsock-pci` with the kernel's vhost-vsock module.
///
/// # Limitations
///
/// See the [module-level documentation](self) for the vsock bridging
/// limitation: this device uses kernel vhost-vsock (AF_VSOCK on the
/// host), while the [`TestVm`](crate::vm::TestVm) infrastructure
/// expects Unix sockets at `$VHOST_SOCKET_$PORT` paths.
fn push_vsock_args(args: &mut Vec<String>) {
    args.extend([
        "-device".into(),
        format!("vhost-vsock-pci,guest-cid={}", VM_GUEST_CID.as_raw()),
    ]);
}

/// Network interfaces.
///
/// Creates three TAP-backed virtio-net-pci devices matching the
/// cloud-hypervisor backend:
///
/// - **mgmt** -- management network.
/// - **fabric1** / **fabric2** -- fabric-facing interfaces.
///
/// Note: QEMU's virtio-net-pci device does not support an MTU property
/// on the command line.  TAP MTU must be configured separately (e.g. via
/// `ip link set`) if non-default MTU is required.  The cloud-hypervisor
/// backend sets MTU in the device configuration, which cloud-hypervisor
/// applies to the TAP devices automatically.
fn push_network_args(args: &mut Vec<String>) {
    for iface in [&IFACE_MGMT, &IFACE_FABRIC1, &IFACE_FABRIC2] {
        args.extend([
            "-netdev".into(),
            format!(
                "tap,id=nd-{id},ifname={tap},script=no,downscript=no",
                id = iface.id,
                tap = iface.tap,
            ),
            "-device".into(),
            format!(
                "virtio-net-pci,netdev=nd-{id},mac={mac}",
                id = iface.id,
                mac = iface.mac,
            ),
        ]);
    }
}

/// Serial console on a Unix socket.
///
/// QEMU creates the socket in server mode (`server=on`) and does not
/// block waiting for a client (`wait=off`).  Console output is buffered
/// until the container tier's kernel-log reader connects.
fn push_serial_args(args: &mut Vec<String>) {
    args.extend([
        "-serial".into(),
        format!("unix:{KERNEL_CONSOLE_SOCKET_PATH},server=on,wait=off"),
    ]);
}

/// QMP control socket for lifecycle commands and event monitoring.
///
/// Creates a chardev socket in server mode and attaches a QMP monitor
/// to it.  The container tier connects to this socket after the QEMU
/// process starts.
fn push_qmp_args(args: &mut Vec<String>) {
    args.extend([
        "-chardev".into(),
        format!("socket,id=qmp0,path={HYPERVISOR_API_SOCKET_PATH},server=on,wait=off"),
        "-mon".into(),
        "chardev=qmp0,mode=control".into(),
    ]);
}

/// SMBIOS tables for test identification and miscellaneous platform
/// settings.
///
/// Embeds the test binary name and test name in SMBIOS OEM strings
/// (type 11), matching the cloud-hypervisor backend's
/// `PlatformConfig.oem_strings`.  Also sets a serial number and UUID
/// in the system information table (type 1).
fn push_platform_args(args: &mut Vec<String>, params: &TestVmParams<'_>) {
    args.extend([
        "-smbios".into(),
        "type=1,serial=dataplane-test,uuid=dff9c8dd-492d-4148-a007-7931f94db852".into(),
        "-smbios".into(),
        format!(
            "type=11,value=exe={bin_name},value=test={test_name}",
            bin_name = params.bin_name,
            test_name = params.test_name,
        ),
    ]);
}

/// Miscellaneous flags.
///
/// - `-display none` -- suppress graphical output.
/// - `-no-reboot` -- exit on guest reboot rather than restarting.
/// - `-no-shutdown` -- pause on guest shutdown rather than exiting, so
///   the QMP event watcher has time to capture the `SHUTDOWN` event
///   before the socket closes.  The [`shutdown`](Qemu::shutdown) method
///   sends `quit` to terminate the paused VMM.
/// - `-device pvpanic` -- enable guest panic detection via the pvpanic
///   PCI device.  When the guest kernel panics, QEMU emits a
///   `GUEST_PANICKED` QMP event.
fn push_misc_args(args: &mut Vec<String>) {
    args.extend([
        "-display".into(),
        "none".into(),
        "-no-reboot".into(),
        "-no-shutdown".into(),
        "-device".into(),
        "pvpanic".into(),
    ]);
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    /// Builds a representative [`TestVmParams`] for use in CLI builder
    /// tests.  The values are arbitrary but realistic.
    fn sample_params() -> TestVmParams<'static> {
        TestVmParams {
            full_bin_path: Path::new("/deps/my_test-abc123"),
            bin_name: "my_test-abc123",
            test_name: "module::test_name",
            iommu: false,
        }
    }

    // ── Machine and CPU ──────────────────────────────────────────────

    #[test]
    fn machine_args_enable_kvm_with_q35() {
        let mut args = Vec::new();
        push_machine_args(&mut args);
        assert!(args.contains(&"-enable-kvm".to_string()));
        assert!(args.contains(&"q35,accel=kvm".to_string()));
        assert!(args.contains(&"host".to_string()));
    }

    #[test]
    fn cpu_args_have_six_vcpus() {
        let mut args = Vec::new();
        push_cpu_args(&mut args);
        let smp = &args[1];
        assert!(smp.starts_with("6,"), "expected 6 vCPUs: {smp}");
    }

    #[test]
    fn cpu_topology_matches_cloud_hypervisor() {
        let mut args = Vec::new();
        push_cpu_args(&mut args);
        let smp = &args[1];
        assert!(smp.contains("sockets=1"), "{smp}");
        assert!(smp.contains("dies=3"), "{smp}");
        assert!(smp.contains("cores=1"), "{smp}");
        assert!(smp.contains("threads=2"), "{smp}");
    }

    // ── Memory ───────────────────────────────────────────────────────

    #[test]
    fn memory_args_use_hugepages_with_sharing() {
        let mut args = Vec::new();
        push_memory_args(&mut args);
        let obj = args
            .iter()
            .find(|a| a.starts_with("memory-backend-file"))
            .unwrap();
        assert!(obj.contains("size=512M"), "{obj}");
        assert!(obj.contains("mem-path=/dev/hugepages"), "{obj}");
        assert!(obj.contains("share=on"), "{obj}");
        assert!(obj.contains("prealloc=on"), "{obj}");
    }

    #[test]
    fn memory_args_include_numa_node() {
        let mut args = Vec::new();
        push_memory_args(&mut args);
        assert!(args.contains(&"node,memdev=mem0".to_string()));
    }

    // ── Kernel ───────────────────────────────────────────────────────

    #[test]
    fn kernel_args_use_kernel_image_path() {
        let mut args = Vec::new();
        push_kernel_args(&mut args, &sample_params());
        let idx = args.iter().position(|a| a == "-kernel").unwrap();
        assert_eq!(args[idx + 1], KERNEL_IMAGE_PATH);
    }

    #[test]
    fn kernel_cmdline_embeds_test_binary_and_name() {
        let mut args = Vec::new();
        push_kernel_args(&mut args, &sample_params());
        let idx = args.iter().position(|a| a == "-append").unwrap();
        let cmdline = &args[idx + 1];
        assert!(cmdline.contains("/deps/my_test-abc123"), "{cmdline}");
        assert!(cmdline.contains("module::test_name"), "{cmdline}");
    }

    #[test]
    fn kernel_cmdline_sets_init_binary() {
        let mut args = Vec::new();
        push_kernel_args(&mut args, &sample_params());
        let idx = args.iter().position(|a| a == "-append").unwrap();
        let cmdline = &args[idx + 1];
        assert!(
            cmdline.contains(&format!("init={INIT_BINARY_PATH}")),
            "{cmdline}"
        );
    }

    #[test]
    fn kernel_cmdline_enables_hugepages() {
        let mut args = Vec::new();
        push_kernel_args(&mut args, &sample_params());
        let idx = args.iter().position(|a| a == "-append").unwrap();
        let cmdline = &args[idx + 1];
        assert!(cmdline.contains("default_hugepagesz=2M"), "{cmdline}");
        assert!(cmdline.contains("hugepagesz=2M"), "{cmdline}");
        assert!(
            cmdline.contains(&format!("hugepages={VM_HUGEPAGE_COUNT}")),
            "{cmdline}"
        );
    }

    #[test]
    fn kernel_cmdline_passes_exact_flag() {
        let mut args = Vec::new();
        push_kernel_args(&mut args, &sample_params());
        let idx = args.iter().position(|a| a == "-append").unwrap();
        let cmdline = &args[idx + 1];
        assert!(cmdline.contains("--exact"), "{cmdline}");
        assert!(cmdline.contains("--no-capture"), "{cmdline}");
        assert!(cmdline.contains("--format=terse"), "{cmdline}");
    }

    // ── Filesystem ───────────────────────────────────────────────────

    #[test]
    fn fs_args_use_virtiofs_tag_and_socket() {
        let mut args = Vec::new();
        push_fs_args(&mut args);
        let chardev = args
            .iter()
            .find(|a| a.starts_with("socket,id=virtiofs0"))
            .unwrap();
        assert!(chardev.contains(VIRTIOFSD_SOCKET_PATH), "{chardev}");
        let device = args
            .iter()
            .find(|a| a.starts_with("vhost-user-fs-pci"))
            .unwrap();
        assert!(device.contains(VIRTIOFS_ROOT_TAG), "{device}");
        assert!(
            device.contains(&format!("queue-size={VIRTIOFS_QUEUE_SIZE}")),
            "{device}"
        );
    }

    // ── vsock ────────────────────────────────────────────────────────

    #[test]
    fn vsock_args_use_guest_cid() {
        let mut args = Vec::new();
        push_vsock_args(&mut args);
        let device = args
            .iter()
            .find(|a| a.starts_with("vhost-vsock-pci"))
            .unwrap();
        assert!(
            device.contains(&format!("guest-cid={}", VM_GUEST_CID.as_raw())),
            "{device}"
        );
    }

    // ── Network ──────────────────────────────────────────────────────

    #[test]
    fn network_args_have_three_interfaces() {
        let mut args = Vec::new();
        push_network_args(&mut args);
        let netdev_count = args.iter().filter(|a| a.starts_with("tap,")).count();
        let device_count = args
            .iter()
            .filter(|a| a.starts_with("virtio-net-pci,"))
            .count();
        assert_eq!(netdev_count, 3);
        assert_eq!(device_count, 3);
    }

    #[test]
    fn all_interfaces_have_unique_mac_addresses() {
        let mut args = Vec::new();
        push_network_args(&mut args);
        let macs: Vec<&str> = args
            .iter()
            .filter_map(|a| {
                a.split(',')
                    .find(|part| part.starts_with("mac="))
                    .map(|p| &p[4..])
            })
            .collect();
        assert_eq!(macs.len(), 3);
        let mut unique = macs.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), 3, "MAC addresses must be unique: {macs:?}");
    }

    #[test]
    fn all_interfaces_have_unique_tap_names() {
        let mut args = Vec::new();
        push_network_args(&mut args);
        let taps: Vec<&str> = args
            .iter()
            .filter_map(|a| {
                a.split(',')
                    .find(|part| part.starts_with("ifname="))
                    .map(|p| &p[7..])
            })
            .collect();
        assert_eq!(taps.len(), 3);
        let mut unique = taps.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), 3, "TAP names must be unique: {taps:?}");
    }

    // ── Serial ───────────────────────────────────────────────────────

    #[test]
    fn serial_args_use_socket_mode() {
        let mut args = Vec::new();
        push_serial_args(&mut args);
        let serial = args.iter().find(|a| a.starts_with("unix:")).unwrap();
        assert!(serial.contains(KERNEL_CONSOLE_SOCKET_PATH), "{serial}");
        assert!(serial.contains("server=on"), "{serial}");
        assert!(serial.contains("wait=off"), "{serial}");
    }

    // ── QMP ──────────────────────────────────────────────────────────

    #[test]
    fn qmp_args_create_control_socket() {
        let mut args = Vec::new();
        push_qmp_args(&mut args);
        let chardev = args
            .iter()
            .find(|a| a.starts_with("socket,id=qmp0"))
            .unwrap();
        assert!(chardev.contains(HYPERVISOR_API_SOCKET_PATH), "{chardev}");
        assert!(chardev.contains("server=on"), "{chardev}");
        assert!(chardev.contains("wait=off"), "{chardev}");
        assert!(args.contains(&"chardev=qmp0,mode=control".to_string()));
    }

    // ── Platform / SMBIOS ────────────────────────────────────────────

    #[test]
    fn platform_args_embed_binary_and_test_name() {
        let mut args = Vec::new();
        push_platform_args(&mut args, &sample_params());
        let oem = args.iter().find(|a| a.starts_with("type=11,")).unwrap();
        assert!(oem.contains("exe=my_test-abc123"), "{oem}");
        assert!(oem.contains("test=module::test_name"), "{oem}");
    }

    #[test]
    fn platform_args_set_serial_and_uuid() {
        let mut args = Vec::new();
        push_platform_args(&mut args, &sample_params());
        let sys = args.iter().find(|a| a.starts_with("type=1,")).unwrap();
        assert!(sys.contains("serial=dataplane-test"), "{sys}");
        assert!(sys.contains("uuid="), "{sys}");
    }

    // ── Misc ─────────────────────────────────────────────────────────

    #[test]
    fn misc_args_disable_display() {
        let mut args = Vec::new();
        push_misc_args(&mut args);
        assert!(args.contains(&"none".to_string()));
    }

    #[test]
    fn misc_args_enable_no_reboot_and_no_shutdown() {
        let mut args = Vec::new();
        push_misc_args(&mut args);
        assert!(args.contains(&"-no-reboot".to_string()));
        assert!(args.contains(&"-no-shutdown".to_string()));
    }

    #[test]
    fn misc_args_enable_pvpanic() {
        let mut args = Vec::new();
        push_misc_args(&mut args);
        assert!(args.contains(&"pvpanic".to_string()));
    }

    // ── Full arg vector ──────────────────────────────────────────────

    #[test]
    fn build_qemu_args_is_nonempty() {
        let args = build_qemu_args(&sample_params());
        assert!(!args.is_empty());
    }

    // ── Event log display ────────────────────────────────────────────

    #[test]
    fn empty_event_log_displays_nothing() {
        let log = QemuEventLog(vec![]);
        assert_eq!(format!("{log}"), "");
    }

    #[test]
    fn event_log_displays_one_line_per_event() {
        let log = QemuEventLog(vec![
            qapi_qmp::Event::SHUTDOWN {
                data: qapi_qmp::SHUTDOWN {
                    guest: true,
                    reason: qapi_qmp::ShutdownCause::guest_shutdown,
                },
                timestamp: serde_json::from_str(r#"{"seconds": 1, "microseconds": 0}"#).unwrap(),
            },
            qapi_qmp::Event::STOP {
                data: qapi_qmp::STOP {},
                timestamp: serde_json::from_str(r#"{"seconds": 2, "microseconds": 0}"#).unwrap(),
            },
        ]);
        let output = format!("{log}");
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 2, "expected 2 lines:\n{output}");
        assert!(lines[0].contains("SHUTDOWN"), "{}", lines[0]);
        assert!(lines[1].contains("STOP"), "{}", lines[1]);
    }

    // ── Verdict computation ──────────────────────────────────────────

    /// A zero-valued timestamp for use in test events.
    fn ts() -> qapi_spec::Timestamp {
        serde_json::from_str(r#"{"seconds": 0, "microseconds": 0}"#).unwrap()
    }

    fn resume_event() -> qapi_qmp::Event {
        qapi_qmp::Event::RESUME {
            data: qapi_qmp::RESUME {},
            timestamp: ts(),
        }
    }

    fn shutdown_event() -> qapi_qmp::Event {
        qapi_qmp::Event::SHUTDOWN {
            data: qapi_qmp::SHUTDOWN {
                guest: true,
                reason: qapi_qmp::ShutdownCause::guest_shutdown,
            },
            timestamp: ts(),
        }
    }

    fn panic_event() -> qapi_qmp::Event {
        qapi_qmp::Event::GUEST_PANICKED {
            data: qapi_qmp::GUEST_PANICKED {
                action: qapi_qmp::GuestPanicAction::pause,
                info: None,
            },
            timestamp: ts(),
        }
    }

    #[test]
    fn clean_shutdown_without_errors() {
        let events = vec![resume_event(), shutdown_event()];
        assert_eq!(
            compute_verdict(&events, false),
            HypervisorVerdict::CleanShutdown,
        );
    }

    #[test]
    fn shutdown_with_stream_errors_is_failure() {
        let events = vec![resume_event(), shutdown_event()];
        assert_eq!(compute_verdict(&events, true), HypervisorVerdict::Failure);
    }

    #[test]
    fn panic_before_shutdown_is_failure() {
        let events = vec![resume_event(), panic_event(), shutdown_event()];
        assert_eq!(compute_verdict(&events, false), HypervisorVerdict::Failure);
    }

    #[test]
    fn panic_without_shutdown_is_failure() {
        let events = vec![resume_event(), panic_event()];
        assert_eq!(compute_verdict(&events, false), HypervisorVerdict::Failure);
    }

    #[test]
    fn stream_ended_without_shutdown_is_failure() {
        let events = vec![resume_event()];
        assert_eq!(compute_verdict(&events, false), HypervisorVerdict::Failure);
    }

    #[test]
    fn empty_event_log_is_failure() {
        assert_eq!(compute_verdict(&[], false), HypervisorVerdict::Failure);
    }

    #[test]
    fn events_after_shutdown_are_ignored_for_verdict() {
        let events = vec![resume_event(), shutdown_event(), panic_event()];
        assert_eq!(
            compute_verdict(&events, false),
            HypervisorVerdict::CleanShutdown,
        );
    }
}
