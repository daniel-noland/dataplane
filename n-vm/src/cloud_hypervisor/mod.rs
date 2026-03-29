// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Cloud-hypervisor [`HypervisorBackend`] implementation.
//!
//! This module encapsulates all
//! [cloud-hypervisor](https://github.com/cloud-hypervisor/cloud-hypervisor)-specific
//! concerns:
//!
//! - **VM configuration** -- translating [`TestVmParams`] into a
//!   cloud-hypervisor [`VmConfig`] via focused sub-builders.
//! - **Process spawning** -- launching the `cloud-hypervisor` binary with
//!   an `--event-monitor` pipe and `--api-socket`.
//! - **Lifecycle control** -- creating and booting the VM via the REST API,
//!   and performing best-effort shutdown.
//! - **Event monitoring** -- delegating to [`events::watch`] to consume
//!   the event stream and produce a [`HypervisorVerdict`].
//!
//! Nothing in this module is used by the generic [`TestVm`](crate::vm::TestVm)
//! machinery except through the [`HypervisorBackend`] trait.
//!
//! The [`events`] submodule contains the cloud-hypervisor event monitor
//! JSON stream decoder and the [`events::watch`] function that consumes
//! the event stream.

pub mod error;
pub(crate) mod events;

pub use self::error::CloudHypervisorError;

use std::os::unix::io::RawFd;
use std::process::Stdio;
use std::sync::Arc;

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
    VIRTIOFSD_SOCKET_PATH, VM_GUEST_CID, VM_RUN_DIR, VsockChannel,
};
use tokio::io::AsyncReadExt;
use tracing::{debug, error};

use crate::abort_on_drop::AbortOnDrop;
use crate::backend::{HypervisorBackend, LaunchedHypervisor};
use crate::error::VmError;
use crate::vm::{TestVmParams, check_kvm_accessible, wait_for_socket};

// ── Constants ────────────────────────────────────────────────────────

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

/// Initial buffer capacity for vsock reader tasks.
const VSOCK_READER_CAPACITY: usize = 32_768;

// ── Public types ─────────────────────────────────────────────────────

/// Cloud-hypervisor [`HypervisorBackend`] implementation.
///
/// Launches a cloud-hypervisor VMM process, configures and boots the VM
/// via its REST API, monitors lifecycle events through the
/// `--event-monitor` pipe, and performs shutdown via the REST API.
#[derive(Debug)]
pub struct CloudHypervisor;

/// Lifecycle controller for a running cloud-hypervisor instance.
///
/// Wraps the generated REST API client behind a mutex (the generated
/// client's methods take `&self` but are not `Sync`).
pub struct CloudHypervisorController {
    client: Arc<tokio::sync::Mutex<dyn DefaultApi>>,
}

/// Collected event log from cloud-hypervisor's `--event-monitor` stream.
///
/// This newtype wraps the raw event vector so that the generic
/// [`VmTestOutput`](crate::vm::VmTestOutput) can store and display
/// backend-specific event data through the [`Display`](std::fmt::Display)
/// bound on [`HypervisorBackend::EventLog`].
///
/// The [`Display`](std::fmt::Display) implementation produces one line per
/// event in a human-readable format suitable for test failure diagnostics.
#[derive(Debug, Default)]
pub struct CloudHypervisorEventLog(pub Vec<events::Event>);

impl std::fmt::Display for CloudHypervisorEventLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for event in &self.0 {
            writeln!(
                f,
                "[{:?}] {:?} - {:?} {:?}",
                event.timestamp, event.source, event.event, event.properties
            )?;
        }
        Ok(())
    }
}

// ── Error conversion ─────────────────────────────────────────────────

impl From<CloudHypervisorError> for VmError {
    fn from(err: CloudHypervisorError) -> Self {
        VmError::Backend(Box::new(err))
    }
}

// ── HypervisorBackend ────────────────────────────────────────────────

impl HypervisorBackend for CloudHypervisor {
    const NAME: &str = "cloud-hypervisor";

    type EventLog = CloudHypervisorEventLog;
    type Controller = CloudHypervisorController;

    async fn launch(params: &TestVmParams<'_>) -> Result<LaunchedHypervisor<Self>, VmError> {
        let (child, event_receiver) = spawn_hypervisor_process().await?;

        let config = build_vm_config(params);

        let client = Arc::new(tokio::sync::Mutex::new(
            cloud_hypervisor_client::socket_based_api_client(HYPERVISOR_API_SOCKET_PATH),
        ));

        client.lock().await.create_vm(config).await.map_err(|e| {
            CloudHypervisorError::VmCreate {
                reason: format!("{e:?}"),
            }
        })?;

        let event_watcher = AbortOnDrop::spawn(async {
            let (events, verdict) = events::watch(event_receiver).await;
            (CloudHypervisorEventLog(events), verdict)
        });

        client
            .lock()
            .await
            .boot_vm()
            .await
            .map_err(|e| CloudHypervisorError::VmBoot {
                reason: format!("{e:?}"),
            })?;

        Ok(LaunchedHypervisor {
            child,
            event_watcher,
            controller: CloudHypervisorController { client },
        })
    }

    async fn shutdown(controller: &Self::Controller) {
        // In the normal path the VM has already powered off (n-it calls
        // reboot(RB_POWER_OFF) or aborts), so these calls will fail
        // harmlessly.  But if the guest init hangs or the shutdown path
        // fails, these calls break the deadlock that would otherwise occur
        // when `collect` waits for the hypervisor process to exit.
        if let Err(err) = controller.client.lock().await.shutdown_vm().await as Result<(), _> {
            debug!("vm shutdown: {err}");
        }
        if let Err(err) = controller.client.lock().await.shutdown_vmm().await as Result<(), _> {
            debug!("vmm shutdown: {err}");
        }
    }

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
}

// ── Process spawning ─────────────────────────────────────────────────

/// Creates the event-monitor pipe, verifies `/dev/kvm`, spawns the
/// cloud-hypervisor binary, and waits for the API socket to appear.
///
/// Returns the child process handle and the event-monitor pipe receiver
/// (which is consumed by [`hypervisor::watch`]).
async fn spawn_hypervisor_process()
-> Result<(tokio::process::Child, tokio::net::unix::pipe::Receiver), VmError> {
    let (event_sender, event_receiver) =
        tokio::net::unix::pipe::pipe().map_err(CloudHypervisorError::EventPipe)?;
    let event_sender = event_sender
        .into_blocking_fd()
        .map_err(CloudHypervisorError::EventSenderFd)?;

    check_kvm_accessible().await?;

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
        .map_err(|e| CloudHypervisorError::FdMapping(format!("{e:?}")))?
        .spawn()
        .map_err(VmError::HypervisorSpawn)?;

    // The first VMM event becoming readable indicates the hypervisor has
    // started.  We then poll until the API socket appears on the
    // filesystem.
    event_receiver
        .readable()
        .await
        .map_err(CloudHypervisorError::EventMonitorNotReadable)?;
    wait_for_socket(HYPERVISOR_API_SOCKET_PATH).await?;

    Ok((hypervisor, event_receiver))
}

// ── VM configuration builders ────────────────────────────────────────
//
// Each builder is a focused function responsible for a single aspect of
// the cloud-hypervisor `VmConfig`.  They can be tested and evolved
// independently; `build_vm_config` composes them into the final config.

/// Builds the complete cloud-hypervisor [`VmConfig`] for a test run.
///
/// The virtio-console is disabled (`Mode::Off`) because test
/// stdout/stderr are forwarded via dedicated
/// [`VsockChannel`](n_vm_protocol::VsockChannel)s instead.
fn build_vm_config(params: &TestVmParams<'_>) -> VmConfig {
    VmConfig {
        payload: build_payload_config(params),
        vsock: Some(VsockConfig {
            cid: VM_GUEST_CID.as_raw() as _,
            socket: VHOST_VSOCK_SOCKET_PATH.into(),
            pci_segment: Some(0),
            ..Default::default()
        }),
        cpus: Some(build_cpu_config()),
        memory: Some(build_memory_config()),
        net: Some(build_network_configs()),
        fs: Some(build_fs_config()),
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
        platform: Some(build_platform_config(params)),
        pvpanic: Some(true),
        landlock_enable: Some(true),
        landlock_rules: Some(vec![LandlockConfig {
            path: VM_RUN_DIR.into(),
            access: "rw".into(),
        }]),
        ..Default::default()
    }
}

/// Builds the kernel payload configuration, including the kernel command
/// line that passes the test binary path and name to the init system.
fn build_payload_config(params: &TestVmParams<'_>) -> PayloadConfig {
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
            full_bin_path = params.full_bin_path.display(),
            test_name = params.test_name,
        )),
        ..Default::default()
    }
}

/// Builds the CPU topology: 6 vCPUs arranged as 3 dies × 1 core × 2
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

/// Builds the memory configuration with hugepage and sharing support.
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

/// Builds the virtiofs filesystem configuration for sharing the container
/// filesystem into the VM.
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

/// Builds the platform metadata configuration, embedding the test binary
/// name and test name in OEM strings for identification.
fn build_platform_config(params: &TestVmParams<'_>) -> PlatformConfig {
    PlatformConfig {
        serial_number: Some("dataplane-test".into()),
        uuid: Some("dff9c8dd-492d-4148-a007-7931f94db852".into()), // arbitrary uuid4
        oem_strings: Some(vec![
            format!("exe={}", params.bin_name),
            format!("test={}", params.test_name),
        ]),
        num_pci_segments: Some(2),
        ..Default::default()
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    /// Builds a representative [`TestVmParams`] for use in config builder
    /// tests.  The values are arbitrary but realistic.
    fn sample_params() -> TestVmParams<'static> {
        TestVmParams {
            full_bin_path: Path::new("/target/debug/deps/my_test-abc123"),
            bin_name: "my_test-abc123",
            test_name: "tests::my_test",
            iommu: false,
        }
    }

    // ── Payload config ───────────────────────────────────────────────

    #[test]
    fn payload_config_uses_kernel_image_path() {
        let params = sample_params();
        let payload = build_payload_config(&params);
        assert_eq!(payload.kernel.as_deref(), Some(KERNEL_IMAGE_PATH));
    }

    #[test]
    fn payload_config_embeds_test_binary_in_cmdline() {
        let params = sample_params();
        let payload = build_payload_config(&params);
        let cmdline = payload.cmdline.as_deref().expect("cmdline should be set");
        assert!(
            cmdline.contains("/target/debug/deps/my_test-abc123"),
            "cmdline should contain the full binary path: {cmdline}",
        );
    }

    #[test]
    fn payload_config_embeds_test_name_in_cmdline() {
        let params = sample_params();
        let payload = build_payload_config(&params);
        let cmdline = payload.cmdline.as_deref().expect("cmdline should be set");
        assert!(
            cmdline.contains("tests::my_test"),
            "cmdline should contain the test name: {cmdline}",
        );
    }

    #[test]
    fn payload_config_sets_init_binary() {
        let params = sample_params();
        let payload = build_payload_config(&params);
        let cmdline = payload.cmdline.as_deref().expect("cmdline should be set");
        assert!(
            cmdline.contains(&format!("init={INIT_BINARY_PATH}")),
            "cmdline should specify the init binary: {cmdline}",
        );
    }

    #[test]
    fn payload_config_enables_hugepages_on_cmdline() {
        let params = sample_params();
        let payload = build_payload_config(&params);
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
        let payload = build_payload_config(&params);
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

    // ── CPU config ───────────────────────────────────────────────────

    #[test]
    fn cpu_config_has_six_vcpus() {
        let cpus = build_cpu_config();
        assert_eq!(cpus.boot_vcpus, 6);
        assert_eq!(cpus.max_vcpus, 6);
    }

    #[test]
    fn cpu_topology_is_three_dies_by_one_core_by_two_threads() {
        let cpus = build_cpu_config();
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

    // ── Memory config ────────────────────────────────────────────────

    #[test]
    fn memory_config_has_expected_size() {
        let mem = build_memory_config();
        assert_eq!(mem.size, VM_MEMORY_BYTES);
    }

    #[test]
    fn memory_config_enables_hugepages_and_sharing() {
        let mem = build_memory_config();
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

    // ── Network config ───────────────────────────────────────────────

    #[test]
    fn network_config_has_three_interfaces() {
        let nets = build_network_configs();
        assert_eq!(nets.len(), 3);
    }

    #[test]
    fn mgmt_interface_is_on_pci_segment_zero_with_standard_mtu() {
        let nets = build_network_configs();
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
        let nets = build_network_configs();
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
        let nets = build_network_configs();
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
        let nets = build_network_configs();
        let taps: Vec<_> = nets.iter().filter_map(|n| n.tap.as_deref()).collect();
        assert_eq!(taps.len(), 3, "all interfaces should have tap names");
        let mut deduped = taps.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(taps.len(), deduped.len(), "all tap names should be unique");
    }

    // ── Filesystem config ────────────────────────────────────────────

    #[test]
    fn fs_config_uses_virtiofs_root_tag_and_socket() {
        let fs = build_fs_config();
        assert_eq!(fs.len(), 1);
        let entry = &fs[0];
        assert_eq!(entry.tag, VIRTIOFS_ROOT_TAG);
        assert_eq!(entry.socket, VIRTIOFSD_SOCKET_PATH);
        assert_eq!(entry.queue_size, VIRTIOFS_QUEUE_SIZE);
    }

    // ── Platform config ──────────────────────────────────────────────

    #[test]
    fn platform_config_embeds_binary_and_test_name_in_oem_strings() {
        let params = sample_params();
        let platform = build_platform_config(&params);
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
        let platform = build_platform_config(&params);
        assert_eq!(platform.num_pci_segments, Some(2));
    }

    // ── Composed VmConfig ────────────────────────────────────────────

    #[test]
    fn vm_config_disables_virtio_console() {
        let params = sample_params();
        let config = build_vm_config(&params);
        let console = config.console.expect("console should be set");
        assert_eq!(console.mode, Mode::Off);
    }

    #[test]
    fn vm_config_serial_uses_socket_mode() {
        let params = sample_params();
        let config = build_vm_config(&params);
        let serial = config.serial.expect("serial should be set");
        assert_eq!(serial.mode, Mode::Socket);
        assert_eq!(serial.socket.as_deref(), Some(KERNEL_CONSOLE_SOCKET_PATH));
    }

    #[test]
    fn vm_config_vsock_uses_guest_cid() {
        let params = sample_params();
        let config = build_vm_config(&params);
        let vsock = config.vsock.expect("vsock should be set");
        assert_eq!(vsock.cid, VM_GUEST_CID.as_raw() as i64);
        assert_eq!(vsock.socket, VHOST_VSOCK_SOCKET_PATH);
    }

    #[test]
    fn vm_config_enables_safety_features() {
        let params = sample_params();
        let config = build_vm_config(&params);
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
        let config = build_vm_config(&params);
        assert_eq!(config.landlock_enable, Some(true));
        let rules = config.landlock_rules.expect("landlock_rules should be set");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].path, VM_RUN_DIR);
        assert_eq!(rules[0].access, "rw");
    }

    // ── Event log display ────────────────────────────────────────────

    #[test]
    fn empty_event_log_displays_nothing() {
        let log = CloudHypervisorEventLog(vec![]);
        assert_eq!(log.to_string(), "");
    }

    #[test]
    fn event_log_displays_one_line_per_event() {
        use std::collections::BTreeMap;
        use std::time::Duration;

        let log = CloudHypervisorEventLog(vec![
            events::Event {
                timestamp: Duration::from_secs(0),
                source: events::Source::Vmm,
                event: events::EventType::Starting,
                properties: BTreeMap::new(),
            },
            events::Event {
                timestamp: Duration::from_secs(1),
                source: events::Source::Vmm,
                event: events::EventType::Shutdown,
                properties: BTreeMap::new(),
            },
        ]);
        let output = log.to_string();
        let lines: Vec<_> = output.lines().collect();
        assert_eq!(lines.len(), 2, "should have one line per event: {output}");
    }
}
