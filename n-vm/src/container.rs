//! Docker container management for the host tier of the `#[in_vm]` test
//! infrastructure.
//!
//! This module launches a privileged Docker container with the devices and
//! capabilities required to boot a cloud-hypervisor VM, then re-executes the
//! test binary inside it.

use bollard::query_parameters::{
    CreateContainerOptions, InspectContainerOptions, RemoveContainerOptions, StartContainerOptions,
};
use bollard::secret::{
    ContainerCreateBody, DeviceMapping, HostConfig, MountBindOptions, RestartPolicy,
    RestartPolicyNameEnum,
};
use n_vm_protocol::{
    CONTAINER_IMAGE, CONTAINER_PLATFORM, ENV_IN_TEST_CONTAINER, ENV_MARKER_VALUE,
    VM_ROOT_SHARE_PATH, VM_RUN_DIR,
};
use tokio_stream::StreamExt;

// ── Constants ────────────────────────────────────────────────────────

/// Linux capabilities required inside the test container.
const REQUIRED_CAPS: [&str; 6] = [
    "SYS_CHROOT",       // for chroot (required by virtiofsd)
    "SYS_RAWIO",        // for af-packet
    "IPC_LOCK",         // for hugepages
    "NET_ADMIN",        // for tap device creation and network interface configuration
    "NET_RAW",          // for raw socket access in network tests
    "NET_BIND_SERVICE", // for vsocket listeners
];

/// Device nodes that must be mapped into the container.
const REQUIRED_DEVICES: [&str; 4] = [
    "/dev/kvm",         // to launch VMs
    "/dev/vhost-vsock", // for vsock communication with the VM
    "/dev/vhost-net",   // for vhost-net backed network interfaces
    "/dev/net/tun",     // for tap device creation
];

// ── ContainerTestResult ──────────────────────────────────────────────

/// The result of running a test inside a Docker container.
///
/// This is a lightweight wrapper that avoids exposing the `bollard` crate's
/// [`ContainerState`](bollard::secret::ContainerState) type as part of the
/// public API.
#[derive(Debug)]
pub struct ContainerTestResult {
    /// The exit code of the container's main process, if available.
    pub exit_code: Option<i64>,
}

// ── Helpers ──────────────────────────────────────────────────────────

/// Creates a read-only private bind mount from `source` to `target`.
///
/// Both mounts in the container configuration (the binary directory itself
/// and its mirror under [`VM_ROOT_SHARE_PATH`]) share the same flags; this
/// helper eliminates the duplication.
fn read_only_bind_mount(source: &str, target: String) -> bollard::models::Mount {
    bollard::models::Mount {
        source: Some(source.into()),
        target: Some(target),
        typ: Some(bollard::secret::MountTypeEnum::BIND),
        read_only: Some(true),
        bind_options: Some(MountBindOptions {
            propagation: Some(
                bollard::secret::MountBindOptionsPropagationEnum::PRIVATE,
            ),
            non_recursive: Some(true),
            create_mountpoint: Some(true),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// Parameters that vary per test invocation and feed into the container
/// configuration.
///
/// Everything else in the [`ContainerCreateBody`] is an infrastructure
/// default derived from the module-level constants.
struct ContainerParams<'a> {
    /// Full path to the test binary (e.g. `/path/to/deps/my_test-abc123`).
    bin_path: &'a str,
    /// Canonicalized directory that contains the test binary.
    bin_dir: &'a str,
    /// Fully-qualified test name (e.g. `module::test_name`).
    test_name: &'a str,
    /// Effective UID of the calling process.
    uid: u32,
    /// Effective GID of the calling process.
    gid: u32,
    /// GIDs of the groups that own the required device nodes and the Docker
    /// socket.  These are added via `--group-add` so the container process
    /// can access the devices without running as root.
    device_groups: Vec<String>,
}

/// Builds the [`ContainerCreateBody`] for a test run.
///
/// This function separates the **what** (image, capabilities, devices,
/// mounts, environment) from the **where** (test binary path, test name)
/// so that the orchestration code in [`run_test_in_vm`] stays focused on
/// lifecycle management.
fn build_container_config(params: &ContainerParams<'_>) -> ContainerCreateBody {
    let ContainerParams {
        bin_path,
        bin_dir,
        test_name,
        uid,
        gid,
        device_groups,
    } = params;

    let cap_add: Vec<String> = REQUIRED_CAPS.iter().map(|&c| c.into()).collect();
    let devices: Vec<DeviceMapping> = REQUIRED_DEVICES
        .iter()
        .map(|&path| DeviceMapping {
            path_on_host: Some(path.into()),
            path_in_container: Some(path.into()),
            cgroup_permissions: Some("rwm".into()),
        })
        .collect();

    let cmd: Vec<String> = [bin_path.to_string()]
        .into_iter()
        .chain([
            test_name.to_string(),
            "--exact".into(),
            "--format=terse".into(),
        ])
        .collect();

    let mounts = vec![
        // Mount the test binary directory at the same path inside the
        // container so that argv[0] resolves correctly.
        read_only_bind_mount(bin_dir, bin_dir.to_string()),
        // Mirror the binary directory under VM_ROOT_SHARE_PATH so that
        // virtiofsd can expose it to the VM guest via virtiofs.
        read_only_bind_mount(
            bin_dir,
            format!("{VM_ROOT_SHARE_PATH}/{bin_dir}"),
        ),
    ];

    let tmpfs = {
        let mut map = std::collections::HashMap::new();
        map.insert(
            VM_RUN_DIR.into(),
            format!("nodev,noexec,nosuid,uid={uid},gid={gid}"),
        );
        map
    };

    ContainerCreateBody {
        entrypoint: None,
        cmd: Some(cmd),
        image: Some(CONTAINER_IMAGE.into()),
        network_disabled: Some(true),
        env: Some(vec![
            format!("{ENV_IN_TEST_CONTAINER}={ENV_MARKER_VALUE}"),
            "RUST_BACKTRACE=1".into(),
        ]),
        user: Some(format!("{uid}:{gid}")),
        host_config: Some(HostConfig {
            devices: Some(devices),
            group_add: Some(device_groups.clone()),
            init: Some(true),
            network_mode: Some("none".into()),
            restart_policy: Some(RestartPolicy {
                name: Some(RestartPolicyNameEnum::NO),
                ..Default::default()
            }),
            auto_remove: Some(false),
            readonly_rootfs: Some(true),
            mounts: Some(mounts),
            tmpfs: Some(tmpfs),
            privileged: Some(false),
            cap_add: Some(cap_add),
            cap_drop: Some(vec!["ALL".into()]),
            ..Default::default()
        }),
        ..Default::default()
    }
}

// ── run_test_in_vm ───────────────────────────────────────────────────

/// Launches a Docker container and re-runs the current test binary inside it.
///
/// This is the **host-tier** entry point, called from the code generated by
/// `#[in_vm]` when neither `IN_VM` nor `IN_TEST_CONTAINER` is set (i.e. a
/// normal `cargo test` invocation).  It:
///
/// 1. Connects to the local Docker daemon.
/// 2. Creates a container from the `n-vm` test image with the required devices
///    (`/dev/kvm`, `/dev/vhost-vsock`, `/dev/vhost-net`, `/dev/net/tun`) and
///    Linux capabilities (`SYS_CHROOT`, `NET_ADMIN`, etc.).
/// 3. Bind-mounts the test binary directory into the container.
/// 4. Starts the container with `IN_TEST_CONTAINER=YES` and streams its
///    stdout/stderr to the host's stdout/stderr.
/// 5. Waits for the container to exit and returns a [`ContainerTestResult`].
///
/// The type parameter `F` is used only to derive the test name via
/// [`std::any::type_name`]; the function itself is never called in this tier.
pub fn run_test_in_vm<F: FnOnce()>(_test_fn: F) -> ContainerTestResult {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio runtime for test container");

    runtime.block_on(async {
        // ── Resolve test identity and binary paths ───────────────────
        let (_, test_name) = std::any::type_name::<F>()
            .split_once("::")
            .expect("type_name did not contain '::' separator for test name");
        let bin_path = std::fs::read_link("/proc/self/exe")
            .expect("failed to read /proc/self/exe symlink");
        let bin_parent = bin_path
            .parent()
            .expect("test binary path has no parent directory");
        let bin_dir = std::fs::canonicalize(bin_parent)
            .expect("failed to canonicalize test binary directory");
        let bin_dir_str = bin_dir
            .to_str()
            .expect("test binary directory path is not valid UTF-8");
        let bin_path_str = bin_path
            .to_str()
            .expect("test binary path is not valid UTF-8");

        // ── Resolve device group ownership ───────────────────────────
        // The container process runs as the current user.  To access the
        // required device nodes we add the owning groups via --group-add.
        use std::os::unix::fs::MetadataExt;
        let docker_host = std::env::var("DOCKER_HOST")
            .unwrap_or("/var/run/docker.sock".into())
            .trim_start_matches("unix://")
            .to_string();
        let required_files: [String; 4] = [
            "/dev/kvm".into(),
            "/dev/vhost-vsock".into(),
            "/dev/vhost-net".into(),
            docker_host,
        ];
        let mut device_groups: Vec<String> = required_files
            .iter()
            .map(|path| {
                std::fs::metadata(path)
                    .unwrap_or_else(|e| panic!("failed to stat required device {path}: {e}"))
                    .gid()
                    .to_string()
            })
            .collect();
        device_groups.sort_unstable();
        device_groups.dedup();

        // ── Build container configuration ────────────────────────────
        let uid = nix::unistd::getuid().as_raw();
        let gid = nix::unistd::getgid().as_raw();
        let config = build_container_config(&ContainerParams {
            bin_path: bin_path_str,
            bin_dir: bin_dir_str,
            test_name,
            uid,
            gid,
            device_groups,
        });

        // ── Create and start the container ───────────────────────────
        let client = bollard::Docker::connect_with_unix_defaults()
            .expect("failed to connect to Docker daemon");
        let container = client
            .create_container(
                Some(CreateContainerOptions {
                    name: None,
                    platform: CONTAINER_PLATFORM.into(),
                }),
                config,
            )
            .await
            .expect("failed to create Docker container");
        client
            .start_container(&container.id, None::<StartContainerOptions>)
            .await
            .expect("failed to start Docker container");

        // ── Stream container logs to host stdout/stderr ──────────────
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
                        eprint!("{}", String::from_utf8_lossy(&message));
                    }
                    bollard::container::LogOutput::StdOut { message }
                    | bollard::container::LogOutput::Console { message } => {
                        print!("{}", String::from_utf8_lossy(&message));
                    }
                    bollard::container::LogOutput::StdIn { .. } => unreachable!(),
                },
                Err(e) => {
                    panic!("error reading container logs: {e:#?}");
                }
            }
        }

        // ── Collect exit status and clean up ─────────────────────────
        let state = client
            .inspect_container(&container.id, None::<InspectContainerOptions>)
            .await
            .expect("failed to inspect container after exit")
            .state
            .expect("container inspection returned no state");
        client
            .remove_container(&container.id, None::<RemoveContainerOptions>)
            .await
            .expect("failed to remove container");

        ContainerTestResult {
            exit_code: state.exit_code,
        }
    })
}