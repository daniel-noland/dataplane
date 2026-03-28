use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use bollard::query_parameters::{
    CreateContainerOptions, InspectContainerOptions, RemoveContainerOptions, StartContainerOptions,
};
use bollard::secret::{
    ContainerCreateBody, ContainerState, DeviceMapping, HostConfig, MountBindOptions,
    RestartPolicy, RestartPolicyNameEnum,
};
use cloud_hypervisor_client::apis::DefaultApi;
use cloud_hypervisor_client::models::console_config::Mode;
use cloud_hypervisor_client::models::{
    ConsoleConfig, CpuTopology, CpusConfig, FsConfig, LandlockConfig, MemoryConfig, NetConfig,
    PayloadConfig, PlatformConfig, VmConfig, VsockConfig,
};
use serde::Deserialize;
use tokio::io::AsyncReadExt;
use tokio_stream::StreamExt;

use command_fds::{CommandFdExt, FdMapping};
use serde_json::StreamDeserializer;
use tokio_util::bytes::{Buf, BytesMut};
use tracing::{debug, error};

pub use n_vm_macros::in_vm;

#[macro_export]
macro_rules! fatal {
    ($msg:expr) => {
        error!($msg);
        panic!($msg);
    };
}

mod hypervisor {
    use std::{collections::BTreeMap, time::Duration};

    use serde::Deserialize;

    #[derive(Debug, Copy, Clone, serde::Deserialize)]
    pub enum Source {
        #[serde(rename = "vm")]
        Vm,
        #[serde(rename = "vmm")]
        Vmm,
        #[serde(rename = "guest")]
        Guest,
        #[serde(rename = "virtio-device")]
        VirtioDevice,
    }

    #[derive(Debug, Copy, Clone, serde::Deserialize)]
    pub enum EventType {
        #[serde(rename = "starting")]
        Starting,
        #[serde(rename = "booting")]
        Booting,
        #[serde(rename = "booted")]
        Booted,
        #[serde(rename = "activated")]
        Activated,
        #[serde(rename = "deleted")]
        Deleted,
        #[serde(rename = "shutdown")]
        Shutdown,
        #[serde(rename = "panic")]
        Panic,
    }

    #[derive(Debug, Clone, serde::Deserialize)]
    pub struct Event {
        pub timestamp: Duration,
        pub source: Source,
        pub event: EventType,
        #[serde(deserialize_with = "deserialize_null_default")]
        pub properties: BTreeMap<String, String>,
    }

    fn deserialize_null_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
    where
        T: Default + serde::Deserialize<'de>,
        D: serde::Deserializer<'de>,
    {
        let opt = Option::deserialize(deserializer)?;
        Ok(opt.unwrap_or_default())
    }
}

async fn launch_virtiofsd(path: impl AsRef<str>) -> tokio::process::Child {
    let uid = nix::unistd::getuid().as_raw();
    let gid = nix::unistd::getuid().as_raw();
    // capctl::ambient::raise(capctl::Cap::NET_ADMIN).unwrap();
    tokio::process::Command::new("/bin/virtiofsd")
        .args([
            "--shared-dir".to_string(),
            path.as_ref().to_string(),
            "--readonly".to_string(),
            "--tag".to_string(),
            "root".to_string(),
            "--socket-path".to_string(),
            "/vm/virtiofsd.sock".to_string(),
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
        .unwrap()
}

pub struct VmTestOutput {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
    pub console: String,
    pub init_trace: String,
    pub virtiofsd_stdout: String,
    pub virtiofsd_stderr: String,
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

pub async fn run_in_vm<F: FnOnce()>(_: F) -> VmTestOutput {
    let test_name = std::any::type_name::<F>().trim_start_matches("&");
    let full_bin_name = std::env::args().next().unwrap(); // TODO: use /proc/self/exe readlink
    let (_share_path, bin_name) = full_bin_name.rsplit_once("/").unwrap();
    let virtiofsd = launch_virtiofsd("/vm.root").await;
    let listen = tokio::net::UnixListener::bind("/vm/vhost.vsock_123456").unwrap();
    let init_system_trace = tokio::spawn(async move {
        const CAPACITY_GUESS: usize = 32_768;
        let mut init_system_trace = Vec::with_capacity(CAPACITY_GUESS);
        let (mut connection, _) = listen.accept().await.unwrap();
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
    let (_, test_name) = test_name.split_once("::").unwrap();
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
            cid: 3,
            socket: "/vm/vhost.vsock".into(),
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
            tag: "root".into(),
            socket: "/vm/virtiofsd.sock".into(),
            num_queues: 1,
            queue_size: 1024,
            id: Some("root".into()),
            ..Default::default()
        }]),
        console: Some(ConsoleConfig::new(Mode::Tty)),
        serial: Some(ConsoleConfig {
            // mode: Mode::File,
            mode: Mode::Socket,
            // file: Some("/vm/kernel.log".into()),
            socket: Some("/vm/kernel.sock".into()),
            ..Default::default()
        }),
        iommu: Some(false),
        watchdog: Some(true),
        platform: Some(PlatformConfig {
            serial_number: Some("datataplane-test".into()),
            uuid: Some("dff9c8dd-492d-4148-a007-7931f94db852".into()), // arbitrary uuid4
            oem_strings: Some(vec![format!("exe={bin_name}"), format!("test={test_name}")]),
            num_pci_segments: Some(2),
            ..Default::default()
        }),
        pvpanic: Some(true),
        landlock_enable: Some(true),
        landlock_rules: Some(vec![LandlockConfig {
            path: "/vm".into(),
            access: "rw".into(),
        }]),
        ..Default::default()
    };

    let (event_sender, event_receiver) = tokio::net::unix::pipe::pipe().unwrap();
    let event_sender = event_sender.into_blocking_fd().unwrap();
    let vmm_socket_path = "/vm/hypervisor.sock";

    tokio::fs::try_exists("/dev/kvm").await.unwrap();

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
        .unwrap()
        .spawn()
        .unwrap();

    // the first vmm event is "readable" when they hypervisor starts.  This also indicates that the api socket should exist.
    event_receiver.readable().await.unwrap();
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
                // let mut stderr = process.stderr.unwrap();
                panic!(
                    "unable to connect to hypervisor: {err}, {:?}",
                    process.stderr.unwrap()
                );
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
    client.lock().await.create_vm(config).await.unwrap();
    let hypervisor_watch = tokio::spawn(watch_hypervisor(event_receiver));
    let kernel_log = tokio::task::spawn(async move {
        let mut loops = 0;
        while loops < 100 {
            loops += 1;
            match tokio::fs::try_exists("/vm/kernel.sock").await {
                Ok(true) => break,
                Ok(false) => {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                Err(err) => {
                    panic!("unable to connect to hypervisor: {err}");
                }
            }
        }
        let mut stream = tokio::net::UnixStream::connect("/vm/kernel.sock")
            .await
            .unwrap();
        let mut kernel_log = String::with_capacity(16_384);
        stream.read_to_string(&mut kernel_log).await.unwrap();
        kernel_log
    });
    client.lock().await.boot_vm().await.unwrap();
    let init_trace = match init_system_trace.await {
        Ok(log) => log,
        Err(err) => {
            format!("unable to join init system task: {err}")
        }
    };
    let (hypervisor_events, hypervisor_verdict) = hypervisor_watch.await.unwrap();
    let hypervisor_output = process.wait_with_output().await.unwrap();
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

    let virtiofsd = virtiofsd.wait_with_output().await.unwrap();
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

pub struct AsyncJsonStreamDecoder<'a, T: Deserialize<'a>> {
    _phantom: std::marker::PhantomData<&'a T>,
}

impl<'a, T> AsyncJsonStreamDecoder<'a, T>
where
    T: Deserialize<'a>,
{
    pub fn new() -> Self {
        Self {
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<'a, T> Default for AsyncJsonStreamDecoder<'a, T>
where
    T: Deserialize<'a>,
{
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub enum AsyncJsonStreamError {
    Json(serde_json::Error),
    Io(std::io::Error),
}

impl From<std::io::Error> for AsyncJsonStreamError {
    fn from(err: std::io::Error) -> Self {
        AsyncJsonStreamError::Io(err)
    }
}

impl<'a> tokio_util::codec::Decoder for AsyncJsonStreamDecoder<'a, hypervisor::Event>
where
    Self: 'a,
{
    type Item = hypervisor::Event;
    type Error = AsyncJsonStreamError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let x = src.as_ref().to_vec();
        let mut des: StreamDeserializer<'_, serde_json::de::SliceRead<'_>, hypervisor::Event> =
            serde_json::Deserializer::from_slice(&x).into_iter::<hypervisor::Event>();
        let next = des.next();
        let bytes_consumed = des.byte_offset();
        match next {
            Some(Ok(value)) => {
                src.advance(bytes_consumed);
                Ok(Some(value))
            }
            Some(Err(err)) => Err(AsyncJsonStreamError::Json(err)),
            None => Ok(None),
        }
    }
}

async fn watch_hypervisor(
    receiver: tokio::net::unix::pipe::Receiver,
) -> (Vec<hypervisor::Event>, bool) {
    let decoder = AsyncJsonStreamDecoder::new();

    let mut reader = tokio_util::codec::FramedRead::new(receiver, decoder);
    let mut hlog = Vec::with_capacity(32);

    let mut success = true;

    loop {
        let event = reader.next().await;
        match event {
            Some(Ok(value)) => {
                hlog.push(value.clone());
                match (value.source, value.event) {
                    (hypervisor::Source::Vmm, hypervisor::EventType::Shutdown) => {
                        return (hlog, success);
                    }
                    (hypervisor::Source::Guest, hypervisor::EventType::Panic) => {
                        success = false;
                        break;
                    }
                    _ => {}
                };
            }
            Some(Err(e)) => {
                error!("{e:#?}");
            }
            None => {
                break;
            }
        }
    }
    (hlog, success)
}

pub fn run_test_in_vm<F: FnOnce()>(_test_fn: F) -> ContainerState {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        const REQUIRED_CAPS: [&str; 6] = [
            "SYS_CHROOT", // for chroot (required by virtiofsd)
            "SYS_RAWIO", // for af-packet
            "IPC_LOCK", // for hugepages
            "NET_ADMIN", // to test creation / configuration of network interfaces and to create tap devices to hook to the vm
            "NET_RAW", // to test creation / configuration of network interfaces and to create tap devices to hook to the vm
            "NET_BIND_SERVICE", // for vsockets
        ];
        const REQUIRED_DEVICES: [&str; 4] = ["/dev/kvm", "/dev/vhost-vsock", "/dev/vhost-net", "/dev/net/tun"];
        let docker_host = std::env::var("DOCKER_HOST").unwrap_or("/var/run/docker.sock".into()).trim_start_matches("unix://").to_string();
        let required_files: [String; _] = [
            "/dev/kvm".into(), // to launch vms
            "/dev/vhost-vsock".into(), // for vsock communication with the vm
            "/dev/vhost-net".into(), // for network communication with the vm
            docker_host, // allows the launch of sibling containers (may not be needed)
        ];
        let (_, test_name) = std::any::type_name::<F>().split_once("::").unwrap();
        let bin_path = std::fs::read_link("/proc/self/exe").unwrap();
        let bin_dir = std::fs::canonicalize(bin_path.parent().unwrap()).unwrap();
        let client = bollard::Docker::connect_with_unix_defaults().unwrap();
        use std::os::unix::fs::MetadataExt;
        let cap_add = REQUIRED_CAPS.map(|cap| cap.into()).into();
        let add_groups = required_files
            .map(|path| std::fs::metadata(&path).unwrap_or_else(|e| panic!("error on {path}: {e}")).gid().to_string())
            .into();
        let devices = REQUIRED_DEVICES
            .map(|path| DeviceMapping {
                path_on_host: Some(path.into()),
                path_in_container: Some(path.into()),
                cgroup_permissions: Some("rwm".into()),
            })
            .into();
        let args = [bin_path.to_str().unwrap().to_string()]
            .into_iter()
            .chain([test_name.to_string(), "--exact".into(), "--format=terse".into()])
            .collect();
        let uid = nix::unistd::getuid().as_raw();
        let gid = nix::unistd::getgid().as_raw();
        let container = client.create_container(
            Some(CreateContainerOptions {
                name: None,
                platform: "x86-64".into(),
            }),
            ContainerCreateBody {
                entrypoint: None,
                cmd: Some(args),
                // TODO: this needs to be dynamic somehow.  Not sure how to do that yet.
                image: Some("ghcr.io/githedgehog/testn/n-vm:v0.0.9".into()),
                network_disabled: Some(true),
                env: Some([
                    "IN_TEST_CONTAINER=YES".into(),
                    "RUST_BACKTRACE=1".into(),
                ].into()),
                user: Some(format!("{uid}:{gid}")),
                host_config: Some(HostConfig {
                    devices: Some(devices),
                    group_add: Some(add_groups),
                    init: Some(true),
                    network_mode: Some("none".into()),
                    restart_policy: Some(RestartPolicy {
                        name: Some(RestartPolicyNameEnum::NO),
                        ..Default::default()
                    }),
                    auto_remove: Some(false),
                    readonly_rootfs: Some(true),
                    mounts: Some([
                        bollard::models::Mount {
                            source: Some(bin_dir.to_str().unwrap().into()),
                            target: Some(bin_dir.to_str().unwrap().into()),
                            typ: Some(bollard::secret::MountTypeEnum::BIND),
                            read_only: Some(true),
                            bind_options: Some(MountBindOptions {
                                propagation: Some(bollard::secret::MountBindOptionsPropagationEnum::PRIVATE),
                                non_recursive: Some(true),
                                create_mountpoint: Some(true),
                                ..Default::default()
                            }),
                            ..Default::default()
                        },
                        bollard::models::Mount {
                            source: Some(bin_dir.to_str().unwrap().into()),
                            target: Some(format!("/vm.root/{}", bin_dir.to_str().unwrap())),
                            typ: Some(bollard::secret::MountTypeEnum::BIND),
                            read_only: Some(true),
                            bind_options: Some(MountBindOptions {
                                propagation: Some(bollard::secret::MountBindOptionsPropagationEnum::PRIVATE),
                                non_recursive: Some(true),
                                create_mountpoint: Some(true),
                                ..Default::default()
                            }),
                            ..Default::default()
                        }
                    ].into()),
                    tmpfs: Some({
                        let mut map = std::collections::HashMap::new();
                        map.insert("/vm".into(), format!("nodev,noexec,nosuid,uid={uid},gid={gid}"));
                        map
                    }),
                    privileged: Some(false),
                    cap_add: Some(cap_add),
                    cap_drop: Some(["ALL".into()].into()),
                    ..Default::default()
                }),
                ..Default::default()
            }
        ).await.unwrap();
        client
            .start_container(&container.id, None::<StartContainerOptions>)
            .await
            .unwrap();
        let mut logs = client.logs(
            &container.id,
            Some(bollard::query_parameters::LogsOptions {
                follow: true,
                stdout: true,
                stderr: true,
                tail: "all".into(),
                ..Default::default()
            }),
        );
        while let Some(log) = logs.next().await {
            match log {
                Ok(msg) => match msg {
                    bollard::container::LogOutput::StdErr { message } => {
                        eprint!(
                            "{message}",
                            message = String::from_utf8_lossy(&message)
                        );
                    }
                    bollard::container::LogOutput::StdOut { message }
                    | bollard::container::LogOutput::Console { message } => {
                        print!(
                            "{message}",
                            message = String::from_utf8_lossy(&message)
                        );
                    }
                    bollard::container::LogOutput::StdIn { .. } => unreachable!(),
                },
                Err(e) => {
                    panic!("{e:#?}");
                }
            }
        }
        let exit = client
            .inspect_container(&container.id, None::<InspectContainerOptions>)
            .await
            .unwrap()
            .state
            .unwrap();
        client
            .remove_container(&container.id, None::<RemoveContainerOptions>)
            .await
            .unwrap();
        exit
    })
}
