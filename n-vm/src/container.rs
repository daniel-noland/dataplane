//! Docker container management for the host tier of the `#[in_vm]` test
//! infrastructure.
//!
//! This module launches a privileged Docker container with the devices and
//! capabilities required to boot a cloud-hypervisor VM, then re-executes the
//! test binary inside it.
//!
//! The public entry point is [`run_test_in_vm`], which orchestrates five
//! focused phases — each implemented as its own helper function so that the
//! orchestrator requires only local reasoning about sequencing:
//!
//! 1. [`resolve_test_params`] — gather test identity, binary paths, device
//!    groups, and process identity.
//! 2. [`build_container_config`] — translate those parameters into a Docker
//!    [`ContainerCreateBody`].
//! 3. [`create_and_start_container`] — create and start the container.
//! 4. [`stream_container_logs`] — forward container stdout/stderr to the
//!    host.
//! 5. [`collect_and_cleanup`] — inspect the exit status and remove the
//!    container.

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
use tracing::warn;

use crate::error::ContainerError;

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

// ── ContainerParams ──────────────────────────────────────────────────

/// Parameters that vary per test invocation and feed into the container
/// configuration.
///
/// Everything else in the [`ContainerCreateBody`] is an infrastructure
/// default derived from the module-level constants.
///
/// All string fields are owned so that parameter resolution
/// ([`resolve_test_params`]) can be cleanly separated from config
/// construction ([`build_container_config`]) without lifetime coupling.
struct ContainerParams {
    /// Full path to the test binary (e.g. `/path/to/deps/my_test-abc123`).
    bin_path: String,
    /// Canonicalized directory that contains the test binary.
    bin_dir: String,
    /// Fully-qualified test name (e.g. `module::test_name`).
    test_name: String,
    /// Effective UID of the calling process.
    uid: u32,
    /// Effective GID of the calling process.
    gid: u32,
    /// GIDs of the groups that own the required device nodes and the Docker
    /// socket.  These are added via `--group-add` so the container process
    /// can access the devices without running as root.
    device_groups: Vec<String>,
}

// ── Helpers: mount construction ──────────────────────────────────────

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

// ── Helpers: parameter resolution ────────────────────────────────────

/// Resolves the GIDs of the groups that own [`REQUIRED_DEVICES`] and the
/// Docker socket.
///
/// The container process runs as the current user.  To access the required
/// device nodes without running as root, we add the owning groups via
/// Docker's `--group-add`.
///
/// # Errors
///
/// Returns [`ContainerError::DeviceNotAccessible`] if any required device
/// or the Docker socket cannot be `stat`'d.
fn resolve_device_groups() -> Result<Vec<String>, ContainerError> {
    use std::os::unix::fs::MetadataExt;

    // Resolve the Docker socket path from DOCKER_HOST, if it points to a
    // local Unix socket.  Non-Unix schemes (e.g. tcp://) have no local
    // file to stat, so the Docker socket group is omitted in that case.
    //
    // Uses `strip_prefix` (not `trim_start_matches`) to avoid stripping
    // the prefix more than once (e.g. "unix://unix://foo" → "foo").
    let docker_socket_path: Option<String> = match std::env::var("DOCKER_HOST") {
        Ok(host) => match host.strip_prefix("unix://") {
            Some(path) => Some(path.to_string()),
            // Non-Unix schemes (e.g. tcp://) have no local socket to stat.
            None if host.contains("://") => None,
            // Bare path with no scheme — treat as a Unix socket path.
            None => Some(host),
        },
        Err(_) => Some("/var/run/docker.sock".into()),
    };

    // Derive the list from REQUIRED_DEVICES (the same array used for
    // --device mappings) plus the Docker socket (when local).  This
    // prevents drift between the two lists — previously /dev/net/tun
    // was in REQUIRED_DEVICES but absent here.
    let required_files: Vec<String> = REQUIRED_DEVICES
        .iter()
        .map(|&s| s.to_string())
        .chain(docker_socket_path)
        .collect();

    let mut groups: Vec<String> = required_files
        .iter()
        .map(|path| {
            std::fs::metadata(path)
                .map(|m| m.gid().to_string())
                .map_err(|source| ContainerError::DeviceNotAccessible {
                    path: path.clone(),
                    source,
                })
        })
        .collect::<Result<Vec<_>, _>>()?;

    groups.sort_unstable();
    groups.dedup();
    Ok(groups)
}

/// Resolves all parameters needed to configure the test container.
///
/// This gathers:
/// - The test name from the type parameter `F` via [`std::any::type_name`].
/// - The test binary path and its parent directory from `/proc/self/exe`.
/// - The effective UID and GID of the calling process.
/// - The device group ownership via [`resolve_device_groups`].
///
/// # Errors
///
/// Returns a [`ContainerError`] if any filesystem lookup or validation
/// step fails.
fn resolve_test_params<F: FnOnce()>() -> Result<ContainerParams, ContainerError> {
    let identity = crate::test_identity::TestIdentity::resolve::<F>();
    let test_name = identity.test_name;

    let bin_path = std::fs::read_link("/proc/self/exe")
        .map_err(ContainerError::BinaryPathRead)?;

    let bin_parent = bin_path
        .parent()
        .ok_or_else(|| ContainerError::NoParentDirectory {
            path: bin_path.clone(),
        })?;

    let bin_dir = std::fs::canonicalize(bin_parent)
        .map_err(ContainerError::BinaryPathCanonicalize)?;

    let bin_dir_str = bin_dir
        .to_str()
        .ok_or_else(|| ContainerError::NonUtf8Path {
            path: bin_dir.clone(),
        })?;

    let bin_path_str = bin_path
        .to_str()
        .ok_or_else(|| ContainerError::NonUtf8Path {
            path: bin_path.clone(),
        })?;

    let device_groups = resolve_device_groups()?;

    Ok(ContainerParams {
        bin_path: bin_path_str.to_owned(),
        bin_dir: bin_dir_str.to_owned(),
        test_name: test_name.to_owned(),
        uid: nix::unistd::getuid().as_raw(),
        gid: nix::unistd::getgid().as_raw(),
        device_groups,
    })
}

// ── Helpers: container configuration ─────────────────────────────────

/// Builds the [`ContainerCreateBody`] for a test run.
///
/// This function separates the **what** (image, capabilities, devices,
/// mounts, environment) from the **where** (test binary path, test name)
/// so that the orchestration code in [`run_test_in_vm`] stays focused on
/// lifecycle management.
/// Builds Docker device mappings from [`REQUIRED_DEVICES`].
///
/// Each device is mapped at the same path inside the container with full
/// read/write/mknod permissions.
fn build_device_mappings() -> Vec<DeviceMapping> {
    REQUIRED_DEVICES
        .iter()
        .map(|&path| DeviceMapping {
            path_on_host: Some(path.into()),
            path_in_container: Some(path.into()),
            cgroup_permissions: Some("rwm".into()),
        })
        .collect()
}

/// Builds the test binary command line for the container entrypoint.
///
/// The command re-invokes the test binary with `--exact` matching so that
/// only the specified test runs inside the container.
fn build_test_command(bin_path: &str, test_name: &str) -> Vec<String> {
    vec![
        bin_path.into(),
        test_name.into(),
        "--exact".into(),
        "--no-capture".into(),
        "--format=terse".into(),
    ]
}

/// Builds the bind mounts for the test binary directory.
///
/// Two mounts are created:
/// - The binary directory at its original path (so argv\[0\] resolves).
/// - A mirror under [`VM_ROOT_SHARE_PATH`] for virtiofs exposure to the VM.
fn build_container_mounts(bin_dir: &str) -> Vec<bollard::models::Mount> {
    vec![
        read_only_bind_mount(bin_dir, bin_dir.to_string()),
        read_only_bind_mount(
            bin_dir,
            format!("{VM_ROOT_SHARE_PATH}/{bin_dir}"),
        ),
    ]
}

/// Builds the tmpfs mounts for the container.
///
/// A single tmpfs is mounted at [`VM_RUN_DIR`] for VM runtime artifacts
/// (sockets, logs, etc.), owned by the specified UID/GID.
fn build_container_tmpfs(uid: u32, gid: u32) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    map.insert(
        VM_RUN_DIR.into(),
        format!("nodev,noexec,nosuid,uid={uid},gid={gid}"),
    );
    map
}

/// Builds the [`ContainerCreateBody`] for a test run.
///
/// This function composes the container configuration from focused
/// sub-builders ([`build_device_mappings`], [`build_test_command`],
/// [`build_container_mounts`], [`build_container_tmpfs`]), keeping the
/// orchestration code focused on the overall structure rather than the
/// details of each component.
fn build_container_config(params: &ContainerParams) -> ContainerCreateBody {
    let ContainerParams {
        bin_path,
        bin_dir,
        test_name,
        uid,
        gid,
        device_groups,
    } = params;

    ContainerCreateBody {
        entrypoint: None,
        cmd: Some(build_test_command(bin_path, test_name)),
        image: Some(CONTAINER_IMAGE.into()),
        network_disabled: Some(true),
        env: Some(vec![
            format!("{ENV_IN_TEST_CONTAINER}={ENV_MARKER_VALUE}"),
            "RUST_BACKTRACE=1".into(),
        ]),
        user: Some(format!("{uid}:{gid}")),
        host_config: Some(HostConfig {
            devices: Some(build_device_mappings()),
            group_add: Some(device_groups.clone()),
            init: Some(true),
            network_mode: Some("none".into()),
            restart_policy: Some(RestartPolicy {
                name: Some(RestartPolicyNameEnum::NO),
                ..Default::default()
            }),
            auto_remove: Some(false),
            readonly_rootfs: Some(true),
            mounts: Some(build_container_mounts(bin_dir)),
            tmpfs: Some(build_container_tmpfs(*uid, *gid)),
            privileged: Some(false),
            cap_add: Some(REQUIRED_CAPS.iter().map(|&c| c.into()).collect()),
            cap_drop: Some(vec!["ALL".into()]),
            ..Default::default()
        }),
        ..Default::default()
    }
}

// ── Helpers: container lifecycle ──────────────────────────────────────

/// Creates and starts a Docker container from the given configuration.
///
/// Returns the container ID on success.
///
/// # Errors
///
/// Returns [`ContainerError::ContainerCreate`] or
/// [`ContainerError::ContainerStart`] if the Docker daemon rejects the
/// request.
async fn create_and_start_container(
    client: &bollard::Docker,
    config: ContainerCreateBody,
) -> Result<String, ContainerError> {
    let container = client
        .create_container(
            Some(CreateContainerOptions {
                name: None,
                platform: CONTAINER_PLATFORM.into(),
            }),
            config,
        )
        .await
        .map_err(ContainerError::ContainerCreate)?;

    client
        .start_container(&container.id, None::<StartContainerOptions>)
        .await
        .map_err(ContainerError::ContainerStart)?;

    Ok(container.id)
}

/// Streams container stdout/stderr to the host's stdout/stderr until the
/// container exits.
///
/// # Errors
///
/// Returns [`ContainerError::LogStream`] if the log stream encounters an
/// error from the Docker daemon.
async fn stream_container_logs(
    client: &bollard::Docker,
    container_id: &str,
) -> Result<(), ContainerError> {
    let mut logs = client.logs(
        container_id,
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
                bollard::container::LogOutput::StdIn { .. } => {
                    warn!("unexpected StdIn log entry from Docker");
                }
            },
            Err(e) => {
                return Err(ContainerError::LogStream(e));
            }
        }
    }

    Ok(())
}

/// Inspects the container's exit status and removes it.
///
/// # Errors
///
/// Returns a [`ContainerError`] if the container cannot be inspected or
/// removed, or if the inspection response is missing the container state.
async fn collect_and_cleanup(
    client: &bollard::Docker,
    container_id: &str,
) -> Result<ContainerTestResult, ContainerError> {
    let state = client
        .inspect_container(container_id, None::<InspectContainerOptions>)
        .await
        .map_err(ContainerError::ContainerInspect)?
        .state
        .ok_or(ContainerError::MissingState)?;

    client
        .remove_container(container_id, None::<RemoveContainerOptions>)
        .await
        .map_err(ContainerError::ContainerRemove)?;

    Ok(ContainerTestResult {
        exit_code: state.exit_code,
    })
}

// ── ContainerGuard ───────────────────────────────────────────────────

/// RAII guard that ensures a Docker container is cleaned up.
///
/// The guard holds a reference to the Docker client and the container ID.
/// The expected usage is:
///
/// 1. Create the guard immediately after the container is started.
/// 2. Perform operations against the running container (e.g. log streaming).
/// 3. Call [`into_result`](Self::into_result) to inspect the exit status
///    and remove the container, defusing the guard.
///
/// If the guard is dropped *without* calling `into_result` (e.g. due to a
/// panic or an early return inserted by a future refactor), the [`Drop`]
/// impl logs the container ID so the leak is visible in test output.
///
/// # Why not async Drop?
///
/// Rust does not support async `Drop`.  The guard cannot perform async
/// container removal in its destructor.  The `Drop` impl instead emits a
/// prominent `tracing::error` with the container ID so that the operator
/// can clean up manually (e.g. `docker rm -f <id>`).
struct ContainerGuard<'a> {
    client: &'a bollard::Docker,
    container_id: String,
    /// Set to `true` once explicit cleanup has been performed via
    /// [`into_result`](Self::into_result).
    defused: bool,
}

impl<'a> ContainerGuard<'a> {
    /// Creates a new guard for a running container.
    fn new(client: &'a bollard::Docker, container_id: String) -> Self {
        Self {
            client,
            container_id,
            defused: false,
        }
    }

    /// Returns a reference to the container ID.
    fn id(&self) -> &str {
        &self.container_id
    }

    /// Performs the explicit inspect + remove lifecycle.
    ///
    /// This marks the guard as defused so that the [`Drop`] impl is a
    /// no-op.  Returns the container's exit status on success.
    async fn into_result(mut self) -> Result<ContainerTestResult, ContainerError> {
        self.defused = true;
        collect_and_cleanup(self.client, &self.container_id).await
    }
}

impl Drop for ContainerGuard<'_> {
    fn drop(&mut self) {
        if !self.defused {
            tracing::error!(
                container_id = %self.container_id,
                "ContainerGuard dropped without explicit cleanup; \
                 the container was NOT removed and may need manual cleanup \
                 (e.g. `docker rm -f {}`)",
                self.container_id,
            );
        }
    }
}

// ── run_test_in_vm ───────────────────────────────────────────────────

/// Launches a Docker container and re-runs the current test binary inside it.
///
/// This is the **host-tier** entry point, called from the code generated by
/// `#[in_vm]` when neither `IN_VM` nor `IN_TEST_CONTAINER` is set (i.e. a
/// normal `cargo test` invocation).  It:
///
/// 1. Resolves the test identity, binary paths, and device group ownership
///    via [`resolve_test_params`].
/// 2. Builds the Docker container configuration via
///    [`build_container_config`].
/// 3. Creates and starts the container via [`create_and_start_container`].
/// 4. Streams container stdout/stderr to the host via
///    [`stream_container_logs`].
/// 5. Collects the exit status and removes the container via
///    [`collect_and_cleanup`].
///
/// The type parameter `F` is used only to derive the test name via
/// [`std::any::type_name`]; the function itself is never called in this tier.
///
/// # Errors
///
/// Returns [`ContainerError`] if any part of the container lifecycle fails
/// (Docker connection, container creation/start, log streaming, inspection,
/// or cleanup).
pub fn run_test_in_vm<F: FnOnce()>(
    _test_fn: F,
) -> Result<ContainerTestResult, ContainerError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio runtime for test container");

    runtime.block_on(async {
        let params = resolve_test_params::<F>()?;
        let config = build_container_config(&params);

        let client = bollard::Docker::connect_with_unix_defaults()
            .map_err(ContainerError::DockerConnect)?;
        let container_id = create_and_start_container(&client, config).await?;

        // Wrap the container in a guard so that if anything between here
        // and the explicit cleanup panics or returns early, the container
        // leak is at least logged (see ContainerGuard::drop).
        let guard = ContainerGuard::new(&client, container_id);

        let log_result = stream_container_logs(&client, guard.id()).await;

        // Explicit cleanup — inspects the exit status and removes the
        // container.  This defuses the guard so its Drop is a no-op.
        let cleanup_result = guard.into_result().await;

        // Propagate the log streaming error first if it occurred — it is
        // the root cause.  But if cleanup also failed, log that error so
        // the container leak is visible even though we cannot return both
        // errors.
        if let (Err(log_err), Err(cleanup_err)) = (&log_result, &cleanup_result) {
            tracing::error!(
                %log_err,
                %cleanup_err,
                "both log streaming and container cleanup failed; \
                 propagating log error, but the container may have leaked",
            );
        }
        log_result?;
        cleanup_result
    })
}