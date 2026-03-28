use bollard::query_parameters::{
    CreateContainerOptions, InspectContainerOptions, RemoveContainerOptions, StartContainerOptions,
};
use bollard::secret::{
    ContainerCreateBody, ContainerState, DeviceMapping, HostConfig, MountBindOptions,
    RestartPolicy, RestartPolicyNameEnum,
};
use n_vm_protocol::{ENV_IN_TEST_CONTAINER, ENV_MARKER_VALUE, VM_ROOT_SHARE_PATH};
use tokio_stream::StreamExt;

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
                    format!("{ENV_IN_TEST_CONTAINER}={ENV_MARKER_VALUE}"),
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
                            target: Some(format!("{}/{}", VM_ROOT_SHARE_PATH, bin_dir.to_str().unwrap())),
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