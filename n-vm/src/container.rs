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
    CreateContainerOptions, InspectContainerOptions, RemoveContainerOptions,
    RemoveContainerOptionsBuilder, StartContainerOptions,
};
use bollard::secret::{
    ContainerCreateBody, DeviceMapping, HostConfig, MountBindOptions, RestartPolicy,
    RestartPolicyNameEnum,
};
use n_vm_protocol::{
    CONTAINER_IMAGE, CONTAINER_PLATFORM, ENV_IN_TEST_CONTAINER, ENV_MARKER_VALUE,
    VM_ROOT_SHARE_PATH, VM_RUN_DIR,
};
use tokio::sync::oneshot;
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
/// ([`resolve`](Self::resolve)) can be cleanly separated from config
/// construction ([`build_config`](Self::build_config)) without lifetime
/// coupling.
///
/// # Usage
///
/// ```ignore
/// let params = ContainerParams::resolve::<F>()?;
/// let config = params.build_config();
/// ```
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

impl ContainerParams {
    // ── Construction ─────────────────────────────────────────────────

    /// Resolves all parameters needed to configure the test container.
    ///
    /// This gathers:
    /// - The test name from the type parameter `F` via
    ///   [`std::any::type_name`].
    /// - The test binary path and its parent directory from
    ///   `/proc/self/exe`.
    /// - The effective UID and GID of the calling process.
    /// - The device group ownership via
    ///   [`resolve_device_groups`](Self::resolve_device_groups).
    ///
    /// # Errors
    ///
    /// Returns a [`ContainerError`] if any filesystem lookup or validation
    /// step fails.
    fn resolve<F: FnOnce()>() -> Result<Self, ContainerError> {
        let identity = crate::test_identity::TestIdentity::resolve::<F>();
        let test_name = identity.test_name;

        let bin_path =
            std::fs::read_link("/proc/self/exe").map_err(ContainerError::BinaryPathRead)?;

        let bin_parent = bin_path
            .parent()
            .ok_or_else(|| ContainerError::NoParentDirectory {
                path: bin_path.clone(),
            })?;

        let bin_dir =
            std::fs::canonicalize(bin_parent).map_err(ContainerError::BinaryPathCanonicalize)?;

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

        let device_groups = Self::resolve_device_groups()?;

        Ok(Self {
            bin_path: bin_path_str.to_owned(),
            bin_dir: bin_dir_str.to_owned(),
            test_name: test_name.to_owned(),
            uid: nix::unistd::getuid().as_raw(),
            gid: nix::unistd::getgid().as_raw(),
            device_groups,
        })
    }

    /// Resolves the GIDs of the groups that own [`REQUIRED_DEVICES`] and
    /// the Docker socket.
    ///
    /// The container process runs as the current user.  To access the
    /// required device nodes without running as root, we add the owning
    /// groups via Docker's `--group-add`.
    ///
    /// # Errors
    ///
    /// Returns [`ContainerError::DeviceNotAccessible`] if any required
    /// device or the Docker socket cannot be `stat`'d.
    fn resolve_device_groups() -> Result<Vec<String>, ContainerError> {
        use std::os::unix::fs::MetadataExt;

        // Resolve the Docker socket path from DOCKER_HOST, if it points
        // to a local Unix socket.  Non-Unix schemes (e.g. tcp://) have no
        // local file to stat, so the Docker socket group is omitted.
        //
        // Uses `strip_prefix` (not `trim_start_matches`) to avoid
        // stripping the prefix more than once (e.g.
        // "unix://unix://foo" → "foo").
        let docker_socket_path: Option<String> = match std::env::var("DOCKER_HOST") {
            Ok(host) => match host.strip_prefix("unix://") {
                Some(path) => Some(path.to_string()),
                // Non-Unix schemes (e.g. tcp://) have no local socket.
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

    // ── Configuration building ───────────────────────────────────────

    /// Builds the [`ContainerCreateBody`] for this test invocation.
    ///
    /// This method composes the container configuration from focused
    /// sub-builders ([`build_device_mappings`](Self::build_device_mappings),
    /// [`build_test_command`](Self::build_test_command),
    /// [`build_mounts`](Self::build_mounts),
    /// [`build_tmpfs`](Self::build_tmpfs)), keeping the overall structure
    /// readable while delegating component details.
    fn build_config(&self) -> ContainerCreateBody {
        ContainerCreateBody {
            entrypoint: None,
            cmd: Some(self.build_test_command()),
            image: Some(CONTAINER_IMAGE.into()),
            network_disabled: Some(true),
            env: Some(vec![
                format!("{ENV_IN_TEST_CONTAINER}={ENV_MARKER_VALUE}"),
                "RUST_BACKTRACE=1".into(),
            ]),
            user: Some(format!("{uid}:{gid}", uid = self.uid, gid = self.gid)),
            host_config: Some(HostConfig {
                devices: Some(Self::build_device_mappings()),
                group_add: Some(self.device_groups.clone()),
                init: Some(true),
                network_mode: Some("none".into()),
                restart_policy: Some(RestartPolicy {
                    name: Some(RestartPolicyNameEnum::NO),
                    ..Default::default()
                }),
                auto_remove: Some(false),
                readonly_rootfs: Some(true),
                mounts: Some(self.build_mounts()),
                tmpfs: Some(self.build_tmpfs()),
                privileged: Some(false),
                cap_add: Some(REQUIRED_CAPS.iter().map(|&c| c.into()).collect()),
                cap_drop: Some(vec!["ALL".into()]),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    /// Builds Docker device mappings from [`REQUIRED_DEVICES`].
    ///
    /// Each device is mapped at the same path inside the container with
    /// full read/write/mknod permissions.
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
    /// The command re-invokes the test binary with `--exact` matching so
    /// that only the specified test runs inside the container.
    fn build_test_command(&self) -> Vec<String> {
        vec![
            self.bin_path.clone(),
            self.test_name.clone(),
            "--exact".into(),
            "--no-capture".into(),
            "--format=terse".into(),
        ]
    }

    /// Builds the bind mounts for the test binary directory.
    ///
    /// Two mounts are created:
    /// - The binary directory at its original path (so argv\[0\] resolves).
    /// - A mirror under [`VM_ROOT_SHARE_PATH`] for virtiofs exposure to
    ///   the VM.
    fn build_mounts(&self) -> Vec<bollard::models::Mount> {
        vec![
            Self::read_only_bind_mount(&self.bin_dir, self.bin_dir.clone()),
            Self::read_only_bind_mount(
                &self.bin_dir,
                format!("{VM_ROOT_SHARE_PATH}/{bin_dir}", bin_dir = self.bin_dir),
            ),
        ]
    }

    /// Builds the tmpfs mounts for the container.
    ///
    /// A single tmpfs is mounted at [`VM_RUN_DIR`] for VM runtime
    /// artifacts (sockets, logs, etc.), owned by the process UID/GID.
    fn build_tmpfs(&self) -> std::collections::HashMap<String, String> {
        let mut map = std::collections::HashMap::new();
        map.insert(
            VM_RUN_DIR.into(),
            format!(
                "nodev,noexec,nosuid,uid={uid},gid={gid}",
                uid = self.uid,
                gid = self.gid,
            ),
        );
        map
    }

    /// Creates a read-only private bind mount from `source` to `target`.
    ///
    /// Both mounts in the container configuration (the binary directory
    /// itself and its mirror under [`VM_ROOT_SHARE_PATH`]) share the same
    /// flags; this helper eliminates the duplication.
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
}

// ── CleanupThread ────────────────────────────────────────────────────

/// A dedicated thread that stands ready to perform emergency container
/// cleanup when the [`ContainerGuard`] is dropped without explicit cleanup.
///
/// The thread blocks on a [`oneshot::Receiver`].  There are two outcomes:
///
/// - **Normal path**: The sender is dropped without sending (via
///   [`defuse`](Self::defuse)).  The receiver returns `Err`, the thread
///   exits immediately, and no cleanup is performed.
/// - **Emergency path**: The [`ContainerGuard::drop`] impl sends the
///   container ID through the channel.  The thread receives it, builds a
///   minimal tokio runtime, and force-removes the container via the Docker
///   API.
///
/// # Why `std::thread` instead of `tokio::task`?
///
/// [`run_test_in_vm`] uses a single-threaded tokio runtime.  During panic
/// unwinding, the runtime may be shutting down, so a `tokio::task::spawn`
/// from [`Drop`] is unreliable.  A dedicated OS thread with its own
/// runtime is fully decoupled from the caller's async context.
struct CleanupThread {
    /// Send the container ID to request emergency cleanup.
    /// Drop without sending to signal "all clear."
    tx: Option<oneshot::Sender<String>>,
    /// Handle to the cleanup thread.  Joined on defuse; detached on
    /// emergency trigger (so that [`Drop`] does not block).
    thread: Option<std::thread::JoinHandle<()>>,
}

impl CleanupThread {
    /// Spawns the cleanup thread with its own clone of the Docker client.
    ///
    /// The thread blocks immediately on the [`oneshot::Receiver`] and does
    /// no work until either [`trigger`](Self::trigger) or
    /// [`defuse`](Self::defuse) is called (or the sender is dropped).
    fn spawn(client: bollard::Docker) -> Self {
        let (tx, rx) = oneshot::channel::<String>();

        let thread = std::thread::Builder::new()
            .name("container-cleanup".into())
            .spawn(move || {
                // Block until we know whether cleanup is needed.
                let container_id = match rx.blocking_recv() {
                    Ok(id) => id,
                    // Sender dropped without sending → explicit cleanup
                    // already happened, nothing to do.
                    Err(_) => return,
                };

                tracing::warn!(
                    %container_id,
                    "performing emergency container cleanup",
                );

                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        tracing::error!(
                            %container_id,
                            error = %e,
                            "failed to build emergency cleanup runtime; \
                             manual removal needed (e.g. `docker rm -f {container_id}`)",
                        );
                        return;
                    }
                };

                rt.block_on(async {
                    let opts = RemoveContainerOptionsBuilder::default()
                        .force(true)
                        .build();
                    match client.remove_container(&container_id, Some(opts)).await {
                        Ok(()) => tracing::warn!(
                            %container_id,
                            "emergency container cleanup succeeded",
                        ),
                        Err(e) => tracing::error!(
                            %container_id,
                            error = %e,
                            "emergency container cleanup failed; \
                             manual removal may be needed \
                             (e.g. `docker rm -f {container_id}`)",
                        ),
                    }
                });
            })
            .expect("failed to spawn container cleanup thread");

        Self {
            tx: Some(tx),
            thread: Some(thread),
        }
    }

    /// Signal that explicit cleanup was performed; the thread will exit
    /// without doing anything.
    ///
    /// Drops the sender (so the receiver sees `RecvError`) and joins the
    /// thread, which should return almost immediately.
    fn defuse(&mut self) {
        // Drop the sender without sending — the receiver unblocks with
        // Err(RecvError) and the thread exits.
        self.tx.take();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }

    /// Send the container ID to trigger emergency cleanup.
    ///
    /// The thread is *detached* (not joined) so that [`Drop`] does not
    /// block waiting for the Docker API call.  The cleanup proceeds in the
    /// background.
    fn trigger(&mut self, container_id: String) {
        if let Some(tx) = self.tx.take() {
            // The only way send() fails is if the receiver was already
            // dropped (thread exited), in which case there is nothing to
            // do.
            let _ = tx.send(container_id);
        }
        // Detach the thread — don't block Drop on the Docker API call.
        self.thread.take();
    }
}

// ── ContainerGuard ───────────────────────────────────────────────────

/// RAII guard that owns a running Docker container and provides lifecycle
/// methods.
///
/// The expected usage is:
///
/// 1. [`create_and_start`](Self::create_and_start) — create the container
///    and return an armed guard.
/// 2. [`stream_logs`](Self::stream_logs) — forward container
///    stdout/stderr to the host.
/// 3. [`into_result`](Self::into_result) — inspect the exit status,
///    remove the container, and defuse the guard.
///
/// If the guard is dropped *without* calling `into_result` (e.g. due to a
/// panic or an early return inserted by a future refactor), the [`Drop`]
/// impl sends the container ID to a [`CleanupThread`] which force-removes
/// the container via the Docker API.
///
/// # Async cleanup via sync Drop
///
/// Rust does not support async `Drop`.  This guard bridges the gap by
/// using a [`tokio::sync::oneshot`] channel whose
/// [`Sender::send`](oneshot::Sender::send) is synchronous (not async),
/// making it safe to call from [`Drop`].  A dedicated [`std::thread`]
/// receives the message and performs the async Docker API call in its own
/// minimal tokio runtime — fully decoupled from whatever runtime (if any)
/// the caller is using.
struct ContainerGuard<'a> {
    client: &'a bollard::Docker,
    container_id: String,
    /// Background thread that will force-remove the container if we send
    /// it the container ID.  Defused on the normal path.
    cleanup: CleanupThread,
    /// Set to `true` once explicit cleanup has been performed via
    /// [`into_result`](Self::into_result).
    defused: bool,
}

impl<'a> ContainerGuard<'a> {
    // ── Construction ─────────────────────────────────────────────────

    /// Creates a Docker container from the given configuration, starts it,
    /// and returns an armed guard.
    ///
    /// This combines container creation, starting, and guard construction
    /// into a single step so that the container is _never_ running without
    /// a guard to clean it up.
    ///
    /// A [`CleanupThread`] is spawned that will stand by to force-remove
    /// the container if this guard is dropped without calling
    /// [`into_result`](Self::into_result).
    ///
    /// # Errors
    ///
    /// Returns [`ContainerError::ContainerCreate`] or
    /// [`ContainerError::ContainerStart`] if the Docker daemon rejects the
    /// request.
    async fn create_and_start(
        client: &'a bollard::Docker,
        config: ContainerCreateBody,
    ) -> Result<ContainerGuard<'a>, ContainerError> {
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

        let cleanup = CleanupThread::spawn(client.clone());
        Ok(Self {
            client,
            container_id: container.id,
            cleanup,
            defused: false,
        })
    }

    // ── Lifecycle ────────────────────────────────────────────────────

    /// Streams container stdout/stderr to the host's stdout/stderr until
    /// the container exits.
    ///
    /// # Errors
    ///
    /// Returns [`ContainerError::LogStream`] if the log stream encounters
    /// an error from the Docker daemon.
    async fn stream_logs(&self) -> Result<(), ContainerError> {
        let mut logs = self.client.logs(
            &self.container_id,
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

    /// Performs the explicit inspect + remove lifecycle.
    ///
    /// This defuses the [`CleanupThread`] (so its background thread exits
    /// without doing anything) and marks the guard so that its [`Drop`]
    /// impl is a no-op.  Returns the container's exit status on success.
    async fn into_result(mut self) -> Result<ContainerTestResult, ContainerError> {
        self.defused = true;
        self.cleanup.defuse();
        self.collect_and_cleanup().await
    }

    /// Inspects the container's exit status and removes it.
    ///
    /// # Errors
    ///
    /// Returns a [`ContainerError`] if the container cannot be inspected
    /// or removed, or if the inspection response is missing the container
    /// state.
    async fn collect_and_cleanup(&self) -> Result<ContainerTestResult, ContainerError> {
        let state = self
            .client
            .inspect_container(&self.container_id, None::<InspectContainerOptions>)
            .await
            .map_err(ContainerError::ContainerInspect)?
            .state
            .ok_or(ContainerError::MissingState)?;

        self.client
            .remove_container(&self.container_id, None::<RemoveContainerOptions>)
            .await
            .map_err(ContainerError::ContainerRemove)?;

        Ok(ContainerTestResult {
            exit_code: state.exit_code,
        })
    }
}

impl Drop for ContainerGuard<'_> {
    fn drop(&mut self) {
        if !self.defused {
            tracing::error!(
                container_id = %self.container_id,
                "ContainerGuard dropped without explicit cleanup; \
                 dispatching emergency container removal",
            );
            self.cleanup.trigger(self.container_id.clone());
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
///    via [`ContainerParams::resolve`].
/// 2. Builds the Docker container configuration via
///    [`ContainerParams::build_config`].
/// 3. Creates and starts the container via
///    [`ContainerGuard::create_and_start`].
/// 4. Streams container stdout/stderr to the host via
///    [`ContainerGuard::stream_logs`].
/// 5. Collects the exit status and removes the container via
///    [`ContainerGuard::into_result`].
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
        let params = ContainerParams::resolve::<F>()?;
        let config = params.build_config();

        let client = bollard::Docker::connect_with_unix_defaults()
            .map_err(ContainerError::DockerConnect)?;

        // The guard is armed at creation — if anything between here and
        // the explicit cleanup panics or returns early, the CleanupThread
        // will force-remove the container.
        let guard = ContainerGuard::create_and_start(&client, config).await?;

        let log_result = guard.stream_logs().await;

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