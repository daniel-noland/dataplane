use std::convert::Infallible;
use std::os::unix::io::{FromRawFd, IntoRawFd};
use std::process::Stdio;

use n_vm_protocol::{ENV_IN_VM, ENV_MARKER_VALUE, TEST_STDERR_VSOCK_PORT, TEST_STDOUT_VSOCK_PORT};
use tokio_vsock::VMADDR_CID_HOST;
use nix::errno::Errno;
use nix::mount::{MntFlags, MsFlags, mount};
use nix::sys::reboot::{RebootMode, reboot};
use nix::sys::signal::{Signal, kill};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::{Pid, sync};

use tokio::process::{Child, Command};
use tokio::signal::unix::{SignalKind, signal};
use tokio::time::{Duration, sleep};
use tracing::{debug, error, info, trace, warn};

/// Minimal init system for running tests inside a cloud-hypervisor VM.
///
/// This unit struct groups all init system functionality as associated methods.
/// It is intended to run as PID 1 and handles filesystem mounting, process
/// lifecycle management, signal forwarding, and clean shutdown.
#[derive(Debug)]
#[non_exhaustive]
pub struct InitSystem;

/// A single entry in the essential-filesystems mount table.
///
/// All fields correspond to the arguments of [`nix::mount::mount`].
struct MountEntry {
    /// Filesystem source (e.g. `"proc"`, `"tmpfs"`).
    source: &'static str,
    /// Mount point path.
    target: &'static str,
    /// Filesystem type.
    fstype: &'static str,
    /// Optional comma-separated mount data (e.g. `"mode=0600,size=5%"`).
    data: Option<&'static str>,
}

/// The filesystems that must be mounted before the test process can run.
///
/// `/dev` is intentionally absent because `CONFIG_DEVTMPFS_MOUNT` is
/// enabled in the kernel configuration, so it is auto-mounted.
///
/// All entries share the security flags `MS_NOSUID | MS_NOEXEC | MS_NODEV`.
const ESSENTIAL_MOUNTS: &[MountEntry] = &[
    MountEntry { source: "proc",    target: "/proc",          fstype: "proc",    data: None },
    MountEntry { source: "sysfs",   target: "/sys",           fstype: "sysfs",   data: None },
    MountEntry { source: "tmpfs",   target: "/tmp",           fstype: "tmpfs",   data: Some("mode=0600,size=5%") },
    MountEntry { source: "tmpfs",   target: "/run",           fstype: "tmpfs",   data: Some("mode=0600,size=5%") },
    MountEntry { source: "cgroup2", target: "/sys/fs/cgroup", fstype: "cgroup2", data: Some("nsdelegate,memory_recursiveprot") },
];

impl InitSystem {
    /// Mounts the essential virtual filesystems required by the guest OS.
    ///
    /// Iterates over [`ESSENTIAL_MOUNTS`] and mounts each entry with the
    /// security flags `nosuid`, `noexec`, `nodev`.  `/dev` is not mounted
    /// here because `CONFIG_DEVTMPFS_MOUNT` is enabled in the kernel
    /// configuration.
    ///
    /// Calls [`fatal!`] (which aborts the process) if any mount fails.
    pub fn mount_essential_filesystems() -> Result<(), std::io::Error> {
        /// Performs a single mount with security flags, aborting on failure.
        fn secure_mount(entry: &MountEntry) {
            let MountEntry { source, target, fstype, data } = entry;
            debug!("mounting {target}");
            if let Err(e) = mount(
                Some(*source),
                *target,
                Some(*fstype),
                MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV,
                *data,
            ) {
                match e {
                    Errno::UnknownErrno => fatal!("unknown error while mounting {target}"),
                    Errno::EPERM => fatal!("permission denied while mounting {target}"),
                    other => fatal!("failed to mount {target}: {other}"),
                }
            }
        }

        for entry in ESSENTIAL_MOUNTS {
            secure_mount(entry);
        }

        debug!("all essential filesystems mounted successfully");
        Ok(())
    }

    /// Spawns the test binary as the main child process.
    ///
    /// Reads the binary path and test name from the kernel command line
    /// arguments (passed via `init=`), sets `IN_VM=YES` so the `#[in_vm]`
    /// macro executes the test body directly, and redirects stdout/stderr to
    /// dedicated vsock streams ([`TEST_STDOUT_VSOCK_PORT`] and
    /// [`TEST_STDERR_VSOCK_PORT`]).
    ///
    /// The container tier must have already bound Unix listeners at the
    /// corresponding vsock listener paths before the VM booted, so these
    /// connections succeed immediately.
    pub async fn spawn_main_process() -> Child {
        debug!("spawning main process");

        let mut args = std::env::args();
        if args.len() < 2 {
            fatal!("no main process specified to init process");
        }

        args.next().expect("argv[0] missing"); // skip self

        // Connect vsock streams for stdout and stderr.  The container tier
        // has already bound Unix listeners at the corresponding paths, so
        // these connections succeed immediately.
        let stdout_addr = vsock::VsockAddr::new(VMADDR_CID_HOST, TEST_STDOUT_VSOCK_PORT);
        let stdout_stream = vsock::VsockStream::connect(&stdout_addr)
            .unwrap_or_else(|e| fatal!("failed to connect stdout vsock: {e}"));

        let stderr_addr = vsock::VsockAddr::new(VMADDR_CID_HOST, TEST_STDERR_VSOCK_PORT);
        let stderr_stream = vsock::VsockStream::connect(&stderr_addr)
            .unwrap_or_else(|e| fatal!("failed to connect stderr vsock: {e}"));

        // SAFETY: `VsockStream::into_raw_fd()` returns a valid, owned file
        // descriptor.  `Stdio::from_raw_fd()` takes ownership of it.  The
        // fd is not used after this point.
        let stdout_stdio = unsafe { Stdio::from_raw_fd(stdout_stream.into_raw_fd()) };
        let stderr_stdio = unsafe { Stdio::from_raw_fd(stderr_stream.into_raw_fd()) };

        let child = Command::new(args.next().expect("argv[1] missing: no test binary specified"))
            .args(args)
            .kill_on_drop(true)
            .stdin(Stdio::inherit())
            .stdout(stdout_stdio)
            .stderr(stderr_stdio)
            .env(ENV_IN_VM, ENV_MARKER_VALUE)
            .env("PATH", "/bin")
            .env("LD_LIBRARY_PATH", "/lib")
            .env("RUST_BACKTRACE", "1")
            .spawn()
            .unwrap_or_else(|e| fatal!("failed to spawn test process: {e}"));

        if let Some(pid) = child.id() {
            debug!("main process spawned with PID: {pid}");
        } else {
            fatal!("unable to determine main PID");
        }
        child
    }

    /// Reaps all orphaned child processes via non-blocking `waitpid`.
    ///
    /// Returns `None` if all reaped processes exited cleanly, or `Some(())`
    /// if any process exited with a non-zero status or was killed by a signal.
    /// This distinction matters because leaked processes are treated as a test
    /// failure.
    #[tracing::instrument(level = "debug")]
    pub fn reap() -> Option<()> {
        let mut success = true;
        const ANY_CHILD: Pid = Pid::from_raw(-1);
        loop {
            match waitpid(ANY_CHILD, Some(WaitPidFlag::WNOHANG)) {
                Ok(WaitStatus::Exited(pid, status)) => {
                    if status != 0 {
                        warn!("orphaned process {pid} exited with status {status}");
                        success = false;
                    }
                }
                Ok(WaitStatus::Signaled(pid, signal, _)) => {
                    warn!("orphaned process {pid} killed by signal {signal}");
                    success = false;
                }
                Ok(WaitStatus::StillAlive) => {
                    break;
                }
                Ok(status) => {
                    debug!("unexpected waitpid status in init: {status:?}");
                    success = false;
                    continue;
                }
                Err(e) => {
                    warn!("unexpected errno from waitpid in init: {e}");
                }
            }
        }
        if success { None } else { Some(()) }
    }

    /// Sends a signal to all processes except init (PID 1).
    ///
    /// Uses `kill(-1, signal)` which targets every process the caller has
    /// permission to signal.  Returns `Some(())` if at least one process
    /// received the signal, `None` if no processes were found (`ESRCH`).
    ///
    /// Calls [`fatal!`] on `EPERM` or unexpected errors, since an init
    /// system that cannot signal its children is in an unrecoverable state.
    #[tracing::instrument(level = "info")]
    pub fn send_signal_to_all_processes(signal: Signal) -> Option<()> {
        // Using PID -1 means "all processes that the calling process has permission to send signals to"
        match kill(Pid::from_raw(-1), signal) {
            Ok(()) => {
                trace!("successfully sent {signal:?} to all processes");
                Some(())
            }
            Err(Errno::ESRCH) => {
                // No processes found - this can happen if we're the only process left
                trace!("no processes found to send {signal:?} to");
                None
            }
            Err(Errno::EPERM) => {
                // Permission denied for some processes - this is fatal to an init system
                fatal!("permission denied when sending signal to all processes: signal {signal:?}");
            }
            Err(e) => {
                fatal!("failed to send signal to all processes: {e}");
            }
        }
    }

    /// Forwards a signal to a specific process, handling the case where the
    /// process has already exited.
    ///
    /// Unlike [`send_signal_to_all_processes`](Self::send_signal_to_all_processes),
    /// this targets a single PID and treats `ESRCH` (no such process) as a
    /// non-fatal condition — the child may have exited between the time the
    /// signal was received and the time we attempt to forward it.
    fn forward_signal(pid: Pid, sig: Signal) {
        if let Err(e) = kill(pid, sig) {
            match e {
                Errno::ESRCH => {
                    debug!("cannot forward {sig:?}: process {pid} already exited");
                }
                other => {
                    error!("failed to forward {sig:?} to process {pid}: {other}");
                }
            }
        }
    }

    /// Terminates all remaining child processes with SIGTERM.
    ///
    /// Sends up to `MAX_SIGTERM_ATTEMPTS` rounds of SIGTERM (with 10 ms
    /// sleeps between rounds), reaping exited processes after each round.
    ///
    /// Returns `None` if no child processes were remaining, or `Some(())`
    /// if processes were found (whether or not they all terminated
    /// successfully).
    #[tracing::instrument(level = "info")]
    pub async fn terminate_remaining_processes() -> Option<()> {
        const MAX_SIGTERM_ATTEMPTS: u8 = 50;
        if Self::list_child_processes().await.is_empty() {
            trace!("no child processes remaining");
            return None;
        }
        if let Some(()) = Self::reap() {
            warn!("test seems to be leaking processes");
        }
        // Send SIGTERM to all processes
        let mut sigs: u8 = 0;
        warn!("sending SIGTERM to all remaining processes");
        while sigs <= MAX_SIGTERM_ATTEMPTS
            && let Some(()) = InitSystem::send_signal_to_all_processes(Signal::SIGTERM)
        {
            sigs += 1;
            sleep(Duration::from_millis(10)).await;
            if let Some(()) = Self::reap() {
                error!("test is leaking processes");
            }
            if Self::list_child_processes().await.is_empty() {
                debug!("no child processes remaining");
                return Some(());
            }
        }
        error!("maximum SIGTERM attempts reached: test did not shut down correctly");
        return Some(());
    }

    /// Unmounts all [`ESSENTIAL_MOUNTS`] in reverse order.
    ///
    /// Syncs the filesystem before and after each unmount.  Uses
    /// `MNT_DETACH` to handle busy mount points, retrying on `EBUSY`.
    /// Calls [`fatal!`] on `EINVAL` or unexpected errors.
    #[tracing::instrument(level = "info")]
    pub fn unmount_filesystems() {
        debug!("syncing filesystems");
        sync();
        debug!("umounting filesystems");
        // Unmount in reverse order of mounting, derived from the same
        // table used by mount_essential_filesystems().
        for mount_point in ESSENTIAL_MOUNTS.iter().rev().map(|e| e.target) {
            debug!("umounting {mount_point}");
            sync();
            loop {
                match nix::mount::umount2(
                    mount_point,
                    MntFlags::MNT_DETACH | MntFlags::UMOUNT_NOFOLLOW,
                ) {
                    Ok(()) => {
                        debug!("successfully unmounted {mount_point}");
                        sync();
                        break;
                    }
                    Err(Errno::EBUSY) => {
                        warn!("{mount_point} can not be un-mounted yet: busy");
                        sync();
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(Errno::EINVAL) => {
                        fatal!("{mount_point} not mounted or invalid");
                    }
                    Err(e) => {
                        fatal!("failed to unmount {mount_point}: {e}");
                    }
                }
            }
        }
        debug!("filesystem umounting completed");
        debug!("final sync");
        sync();
    }

    /// Performs a clean system shutdown.
    ///
    /// 1. Terminates any remaining child processes.
    /// 2. Unmounts all filesystems.
    /// 3. If the test succeeded, powers off the VM via `reboot(RB_POWER_OFF)`.
    /// 4. If the test failed, calls [`fatal!`] which aborts the process,
    ///    triggering a guest panic that the hypervisor detects as a failure.
    ///
    /// This function never returns (its return type is [`Infallible`]).
    #[tracing::instrument(level = "info")]
    pub async fn shutdown_system(success: bool) -> Infallible {
        info!("beginning system shutdown");

        // Terminate all processes using nix signal functions
        let success = Self::terminate_remaining_processes().await.is_none() && success;

        // Final sync and power off
        match tokio::task::spawn_blocking(move || {
            Self::unmount_filesystems();
            if success {
                info!("powering off");
                match reboot(RebootMode::RB_POWER_OFF) {
                    Ok(_) => unreachable!(),
                    Err(e) => {
                        fatal!("failed to power off: {e}");
                    }
                }
            } else {
                fatal!("test failed");
            }
        })
        .await
        {
            Ok(_) => {
                // normally I would use unreachable!() here, but in this case
                // it is better to use fatal!() to help ensure that stdio is flushed.
                fatal!("unreachable code?");
            }
            Err(err) => {
                fatal!("failed to shutdown system: {err}");
            }
        }
    }

    /// Main entry point for the init system.
    ///
    /// Registers signal handlers, mounts filesystems, spawns the test process,
    /// and enters the main event loop.  The event loop forwards signals to the
    /// test process and waits for it to exit, then initiates shutdown.
    ///
    /// This function never returns (its return type is [`Infallible`]).
    #[tracing::instrument(level = "info")]
    pub async fn run() -> Infallible {
        /// Registers a Unix signal handler, aborting via [`fatal!`] on failure.
        ///
        /// An init system that cannot register signal handlers is in an
        /// unrecoverable state, so failure here is fatal.
        fn must_register_signal(kind: SignalKind) -> tokio::signal::unix::Signal {
            signal(kind)
                .unwrap_or_else(|e| fatal!("failed to register signal handler: {e}"))
        }

        info!("starting init system");
        debug!("registering signal handlers");

        // signals to handle in init system
        let mut sigterm = must_register_signal(SignalKind::terminate());

        // benign signals to forward to main process
        // NOTE: we intentionally do not handle SIGCHLD yet.
        // If the test is leaking processes that is a failure criteria we will catch after the main process exits.
        let mut sighup = must_register_signal(SignalKind::hangup());
        let mut siguser1 = must_register_signal(SignalKind::user_defined1());
        let mut siguser2 = must_register_signal(SignalKind::user_defined2());
        let mut sigwindow = must_register_signal(SignalKind::window_change());

        // signals which represent failure if received, but which should still be forwarded to main process
        let mut sigint = must_register_signal(SignalKind::interrupt());
        let mut sigalarm = must_register_signal(SignalKind::alarm());
        let mut sigpipe = must_register_signal(SignalKind::pipe());
        let mut sigquit = must_register_signal(SignalKind::quit());

        debug!("signal handlers registered");

        // Mount essential filesystems
        match tokio::task::spawn_blocking(Self::mount_essential_filesystems).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => fatal!("failed to mount essential filesystems: {e}"),
            Err(e) => fatal!("mount filesystem task panicked: {e}"),
        }

        // Spawn the main process
        let mut child = InitSystem::spawn_main_process().await;

        let pid = match child.id() {
            Some(id) => Pid::from_raw(id as i32),
            None => fatal!("unable to determine PID of spawned test process"),
        };

        let mut success = true;

        // Main event loop
        loop {
            // any non-terminating exit of this loop should cause us to reap orphaned child processes
            tokio::select! {
                // Main process completion
                result = child.wait() => {
                    match result {
                        Ok(status) => {
                            if status.success() {
                                debug!("main process exited successfully with status {status}");
                            } else {
                                error!("main process exited with failure status {status}");
                                success = false;
                            }
                        },
                        Err(e) => {
                            error!("main process error: {e}");
                            success = false;
                        }
                    }
                    break;
                }
                _ = sigterm.recv() => {
                    debug!("received SIGTERM");
                    success = false;
                    Self::forward_signal(pid, Signal::SIGTERM);
                }
                _ = sigint.recv() => {
                    warn!("forwarding SIGINT");
                    success = false;
                    Self::forward_signal(pid, Signal::SIGINT);
                }
                _ = sigalarm.recv() => {
                    warn!("forwarding SIGALRM");
                    success = false;
                    Self::forward_signal(pid, Signal::SIGALRM);
                }
                _ = sigpipe.recv() => {
                    warn!("forwarding PIPE");
                    success = false;
                    Self::forward_signal(pid, Signal::SIGPIPE);
                }
                _ = sigquit.recv() => {
                    warn!("forwarding QUIT");
                    success = false;
                    Self::forward_signal(pid, Signal::SIGQUIT);
                }
                _ = sighup.recv() => {
                    debug!("forwarding SIGHUP");
                    Self::forward_signal(pid, Signal::SIGHUP);
                }
                _ = siguser1.recv() => {
                    debug!("forwarding SIGUSR1");
                    Self::forward_signal(pid, Signal::SIGUSR1);
                }
                _ = siguser2.recv() => {
                    debug!("forwarding SIGUSR2");
                    Self::forward_signal(pid, Signal::SIGUSR2);
                }
                _ = sigwindow.recv() => {
                    trace!("forwarding WINDOW");
                    Self::forward_signal(pid, Signal::SIGWINCH);
                }
            }
        }
        InitSystem::shutdown_system(success).await
    }

    /// Lists all direct child processes of init (PPID == 1) by scanning `/proc`.
    pub async fn list_child_processes() -> Vec<Pid> {
        let mut child_pids = tokio::fs::read_dir("/proc")
            .await
            .unwrap_or_else(|e| fatal!("failed to read /proc: {e}"));
        let mut children = vec![];
        while let Some(process) = child_pids
            .next_entry()
            .await
            .unwrap_or_else(|e| fatal!("failed to read /proc entry: {e}"))
        {
            let Ok(pid) = process.file_name().to_string_lossy().parse::<u32>() else {
                continue;
            };
            let stat = tokio::fs::read_to_string(format!("/proc/{}/stat", pid)).await;
            let Ok(stat) = stat else {
                continue;
            };
            let Some(ppid) = stat.split_whitespace().nth(3) else {
                continue;
            };
            let Ok(ppid) = ppid.parse::<u32>() else {
                continue;
            };
            if ppid == 1 {
                if pid > i32::MAX as u32 {
                    fatal!("pid overflow");
                }
                children.push(Pid::from_raw(pid as i32));
            }
        }
        children
    }
}