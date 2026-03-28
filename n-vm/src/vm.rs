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
    HYPERVISOR_API_SOCKET_PATH, KERNEL_CONSOLE_SOCKET_PATH, VHOST_VSOCK_SOCKET_PATH,
    VIRTIOFSD_SOCKET_PATH, VIRTIOFS_ROOT_TAG, VM_GUEST_CID, VM_ROOT_SHARE_PATH, VM_RUN_DIR,
    vhost_vsock_listener_path,
};
use tokio::io::AsyncReadExt;
use tracing::{debug, error};

use crate::hypervisor;

async fn launch_virtiofsd(path: impl AsRef<str>) -> tokio::process::Child {
    let uid = nix::unistd::getuid().as_raw();
    let gid = nix::unistd::getgid().as_raw();
    // capctl::ambient::raise(capctl::Cap::NET_ADMIN).unwrap();
    tokio::process::Command::new("/bin/virtiofsd")
        .args([
            "--shared-dir".to_string(),
            path.as_ref().to_string(),
            "--readonly".to_string(),
            "--tag".to_string(),
            VIRTIOFS_ROOT_TAG.to_string(),
            "--socket-path".to_string(),
            VIRTIOFSD_SOCKET_PATH.to_string(),
            "--announce-submounts".to_string(),
            "--sandbox=none".to_string(),
            "--rlimit-nofile=0".to_string(),
            format!("--translate-uid=squash-host:0:{uid}:{MAX}", MAX = u32::MAX),
            format!("--translate-gid=squash-host:0:{gid}:{MAX}", MAX = u32::MAX),
        ])
        .stdin(Stdio::null())
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("failed to spawn virtiofsd process")
}

/// Collected output from a test that ran inside a VM.
///
/// This struct aggregates all observable output from the three-tier test
/// execution (hypervisor events, kernel console, init system tracing, and the
/// test's own stdout/stderr).  Its [`Display`](std::fmt::Display) implementation
/// formats everything into labelled sections for easy reading in test failure
/// output.
pub struct VmTestOutput {
    /// Whether the test, hypervisor, and virtiofsd all exited successfully.
    pub success: bool,
    /// Captured stdout from the cloud-hypervisor process.
    pub stdout: String,
    /// Captured stderr from the cloud-hypervisor process.
    pub stderr: String,
    /// Kernel serial console output (from the guest's `ttyS0`).
    pub console: String,
    /// Tracing output from the `n-it` init system, streamed via vsock.
    pub init_trace: String,
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

/// Boots a cloud-hypervisor VM and runs the test function inside it.
///
/// This is the **container-tier** entry point, called from the code generated
/// by `#[in_vm]` when `IN_TEST_CONTAINER=YES`.  It:
///
/// 1. Launches virtiofsd to share the container's root filesystem into the VM.
/// 2. Binds a Unix socket for the init system's vsock tracing stream.
/// 3. Configures and boots a cloud-hypervisor VM with the test binary as the
///    init payload argument.
/// 4. Collects hypervisor events, kernel console output, and init system traces.
/// 5. Shuts down the VM and returns a [`VmTestOutput`] with the results.
///
/// The type parameter `F` is used only to derive the test name via
/// [`std::any::type_name`]; the function itself is never called in this tier.
pub async fn run_in_vm<F: FnOnce()>(_: F) -> VmTestOutput {
    let test_name = std::any::type_name::<F>().trim_start_matches("&");
    let full_bin_name = std::env::args()
        .next()
        .expect("argv[0] missing: cannot determine test binary path");
    let (_share_path, bin_name) = full_bin_name
        .rsplit_once("/")
        .expect("test binary path does not contain a '/' separator");
    let virtiofsd = launch_virtiofsd(VM_ROOT_SHARE_PATH).await;
    let listen = tokio::net::UnixListener::bind(vhost_vsock_listener_path())
        .expect("failed to bind vsock listener unix socket");
    let init_system_trace = tokio::spawn(async move {
        const CAPACITY_GUESS: usize = 32_768;
        let mut init_system_trace = Vec::with_capacity(CAPACITY_GUESS);
        let (mut connection, _) = listen
            .accept()
            .await
            .expect("failed to accept init system vsock connection");
        loop {
            tokio::select! {
                res = connection.read_buf(&mut init_system_trace) => {
                    match res {
                        Ok(bytes) => {
                            if bytes == 0 {
                                break;
                            }
                            tokio::task::yield_now().await;
                        },
                        Err(e) => {
                            error!("{e}");
                            break;
                        },
                    }
                }
            };
        }
        String::from_utf8_lossy(&init_system_trace).to_string()
    });
    let (_, test_name) = test_name
        .split_once("::")
        .expect("type_name did not contain '::' separator for test name");
    let config = VmConfig {
        payload: PayloadConfig {
            firmware: None,
            kernel: Some("/bzImage".into()),
            cmdline: Some(format!(
                "iommu=on intel_iommu=on amd_iommu=on vfio.enable_unsafe_noiommu_mode=1 earlyprintk=ttyS0 console=ttyS0 ro rootfstype=virtiofs root=root default_hugepagesz=2M hugepagesz=2M hugepages=16 init=/bin/n-it {full_bin_name} {test_name} --exact --no-capture --format=terse"
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
            size: 512 * 1024 * 1024, // 512MiB
            mergeable: Some(true),
            shared: Some(true),
            hugepages: Some(true),
            hugepage_size: Some(2 * 1024 * 1024), // 2MiB
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
        console: Some(ConsoleConfig::new(Mode::Tty)),
        serial: Some(ConsoleConfig {
            // mode: Mode::File,
            mode: Mode::Socket,
            // file: Some("/vm/kernel.log".into()),
            socket: Some(KERNEL_CONSOLE_SOCKET_PATH.into()),
            ..Default::default()
        }),
        iommu: Some(false),
        watchdog: Some(true),
        platform: Some(PlatformConfig {
            serial_number: Some("dataplane-test".into()),
            uuid: Some("dff9c8dd-492d-4148-a007-7931f94db852".into()), // arbitrary uuid4
            oem_strings: Some(vec![format!("exe={bin_name}"), format!("test={test_name}")]),
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
    };

    let (event_sender, event_receiver) =
        tokio::net::unix::pipe::pipe().expect("failed to create event monitor pipe");
    let event_sender = event_sender
        .into_blocking_fd()
        .expect("failed to convert event sender to blocking fd");
    let vmm_socket_path = HYPERVISOR_API_SOCKET_PATH;

    tokio::fs::try_exists("/dev/kvm")
        .await
        .expect("/dev/kvm does not exist or is not accessible");

    const EVENT_MONITOR_FD: i32 = 3;
    let process = tokio::process::Command::new("/bin/cloud-hypervisor")
        .args([
            "--api-socket",
            format!("path={}", vmm_socket_path).as_str(),
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
        .expect("failed to set up fd mappings for cloud-hypervisor")
        .spawn()
        .expect("failed to spawn cloud-hypervisor process");

    // the first vmm event is "readable" when they hypervisor starts.  This also indicates that the api socket should exist.
    event_receiver
        .readable()
        .await
        .expect("event monitor pipe not readable after hypervisor start");
    // on the off chance that we get the readable event before the socket is created, loop until it exists
    let mut loops = 0;
    while loops < 100 {
        loops += 1;
        match tokio::fs::try_exists(vmm_socket_path).await {
            Ok(true) => break,
            Ok(false) => {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            Err(err) => {
                panic!("unable to connect to hypervisor: {err}");
            }
        }
    }
    let client = Arc::new(tokio::sync::Mutex::new(
        cloud_hypervisor_client::socket_based_api_client(vmm_socket_path),
    ));
    let mut loops = 0;
    loop {
        match tokio::fs::try_exists(vmm_socket_path).await {
            Ok(true) => break,
            Ok(false) => {
                loops += 1;
                if loops > 100 {
                    panic!("failed to communicate with hypervisor: no api socket found");
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            Err(err) => {
                panic!("unable to communicate with hypervisor: {err}");
            }
        }
    }
    client
        .lock()
        .await
        .create_vm(config)
        .await
        .expect("failed to create VM via hypervisor API");
    let hypervisor_watch = tokio::spawn(hypervisor::watch(event_receiver));
    let kernel_log = tokio::task::spawn(async move {
        let mut loops = 0;
        while loops < 100 {
            loops += 1;
            match tokio::fs::try_exists(KERNEL_CONSOLE_SOCKET_PATH).await {
                Ok(true) => break,
                Ok(false) => {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                Err(err) => {
                    panic!("unable to connect to hypervisor: {err}");
                }
            }
        }
        let mut stream = tokio::net::UnixStream::connect(KERNEL_CONSOLE_SOCKET_PATH)
            .await
            .expect("failed to connect to kernel console socket");
        let mut kernel_log = String::with_capacity(16_384);
        stream
            .read_to_string(&mut kernel_log)
            .await
            .expect("failed to read kernel console output");
        kernel_log
    });
    client
        .lock()
        .await
        .boot_vm()
        .await
        .expect("failed to boot VM via hypervisor API");
    let init_trace = match init_system_trace.await {
        Ok(log) => log,
        Err(err) => {
            format!("unable to join init system task: {err}")
        }
    };
    let (hypervisor_events, hypervisor_verdict) = hypervisor_watch
        .await
        .expect("hypervisor event watcher task panicked");
    let hypervisor_output = process
        .wait_with_output()
        .await
        .expect("failed to collect cloud-hypervisor process output");
    let kernel_log = kernel_log
        .await
        .unwrap_or_else(|err| format!("!!!KERNEL LOG MISSING!!!:\n\n{err:#?}\n\n"));

    match client.lock().await.shutdown_vm().await {
        Ok(()) => {}
        Err(err) => {
            debug!("vm shutdown: {err}");
        }
    };
    match client.lock().await.shutdown_vmm().await {
        Ok(()) => {}
        Err(err) => {
            debug!("vmm shutdown: {err}");
        }
    }

    let virtiofsd = virtiofsd
        .wait_with_output()
        .await
        .expect("failed to collect virtiofsd process output");
    VmTestOutput {
        success: virtiofsd.status.success()
            && hypervisor_verdict
            && hypervisor_output.status.success(),
        stdout: String::from_utf8_lossy(&hypervisor_output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&hypervisor_output.stderr).to_string(),
        console: kernel_log.clone(),
        init_trace,
        virtiofsd_stdout: String::from_utf8_lossy(virtiofsd.stdout.as_slice()).to_string(),
        virtiofsd_stderr: String::from_utf8_lossy(virtiofsd.stderr.as_slice()).to_string(),
        hypervisor_events,
    }
}