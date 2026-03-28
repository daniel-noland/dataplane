use std::convert::Infallible;
use std::process::Stdio;

use n_vm_protocol::{ENV_IN_VM, ENV_MARKER_VALUE};
use nix::errno::Errno;
use nix::mount::{MntFlags, MsFlags, mount};
use nix::sys::reboot::{RebootMode, reboot};
use nix::sys::signal::{Signal, kill};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::{Pid, sync};
use tokio::io::AsyncWriteExt;
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

impl InitSystem {
    /// Mounts the essential virtual filesystems required by the guest OS.
    ///
    /// Mounts `/proc`, `/sys`, `/tmp`, `/run`, and `/sys/fs/cgroup` with
    /// appropriate security flags (`nosuid`, `noexec`, `nodev`).  `/dev` is
    /// not mounted here because `CONFIG_DEVTMPFS_MOUNT` is enabled in the
    /// kernel configuration.
    ///
    /// Calls [`fatal!`] (which aborts the process) if any mount fails.
    pub fn mount_essential_filesystems() -> Result<(), std::io::Error> {
        fn fail_to_mount(mount: &'static str, e: Errno) -> ! {
            match e {
                Errno::UnknownErrno => {
                    fatal!("unknown error while mounting {mount}");
                }
                Errno::EPERM => {
                    fatal!("permission denied while mounting {mount}");
                }
                other => {
                    fatal!("failed to mount {mount}: {other}");
                }
            }
        }

        // Mount /proc with security options
        debug!("mounting /proc");
        if let Err(e) = mount(
            Some("proc"),
            "/proc",
            Some("proc"),
            MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV,
            None::<&str>,
        ) {
            fail_to_mount("/proc", e)
        };

        // Mount /sys with security options
        debug!("mounting /sys");
        if let Err(e) = mount(
            Some("sysfs"),
            "/sys",
            Some("sysfs"),
            MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV,
            None::<&str>,
        ) {
            fail_to_mount("/sys", e)
        }

        // no need to mount /dev because CONFIG_DEVTMPFS_MOUNT is enabled in the kernel.  /dev is auto mounted

        // Mount /tmp as tmpfs
        debug!("mounting /tmp");
        if let Err(e) = mount(
            Some("tmpfs"),
            "/tmp",
            Some("tmpfs"),
            MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV,
            Some("mode=0600,size=5%"),
        ) {
            fail_to_mount("/tmp", e)
        };

        // Mount /run as tmpfs
        debug!("mounting /run");
        if let Err(e) = mount(
            Some("tmpfs"),
            "/run",
            Some("tmpfs"),
            MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV,
            Some("mode=0600,size=5%"),
        ) {
            fail_to_mount("/run", e)
        }

        // Mount /sys/fs/group with security options
        debug!("mounting /sys/fs/cgroup");
        if let Err(e) = mount(
            Some("cgroup2"),
            "/sys/fs/cgroup",
            Some("cgroup2"),
            MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV,
            Some("nsdelegate,memory_recursiveprot"),
        ) {
            fail_to_mount("/sys/fs/cgroup", e)
        }

        debug!("all essential filesystems mounted successfully");
        Ok(())
    }

    /// Spawns the test binary as the main child process.
    ///
    /// Reads the binary path and test name from the kernel command line
    /// arguments (passed via `init=`), sets `IN_VM=YES` so the `#[in_vm]`
    /// macro executes the test body directly, and redirects stdout/stderr to
    /// the hypervisor console (`/dev/hvc0`).
    ///
    /// Returns the console file handle (for flushing) and the child process.
    pub async fn spawn_main_process() -> (tokio::fs::File, Child) {
        debug!("spawning main process");

        let mut args = std::env::args();
        if args.len() < 2 {
            fatal!("no main process specified to init process");
        }

        let mut console = tokio::fs::OpenOptions::new()
            .read(false)
            .append(true)
            .create_new(false)
            .open("/dev/hvc0")
            .await
            .unwrap();
        console.set_max_buf_size(8_192);

        args.next().unwrap(); // skip self

        // TODO: convert from using hvc0 to using a vsock
        let child = Command::new(args.next().unwrap())
            .args(args)
            .kill_on_drop(true)
            .stdin(Stdio::inherit())
            .stderr(console.try_clone().await.unwrap().into_std().await)
            .stdout(console.try_clone().await.unwrap().into_std().await)
            .env(ENV_IN_VM, ENV_MARKER_VALUE)
            .env("PATH", "/bin")
            .env("LD_LIBRARY_PATH", "/lib")
            .env("RUST_BACKTRACE", "1")
            .spawn()
            .unwrap();

        if let Some(pid) = child.id() {
            debug!("main process spawned with PID: {pid}");
        } else {
            fatal!("unable to determine main PID");
        }
        (console, child)
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

    /// Unmounts all essential filesystems in reverse order of mounting.
    ///
    /// Syncs the filesystem before and after each unmount.  Uses
    /// `MNT_DETACH` to handle busy mount points, retrying on `EBUSY`.
    /// Calls [`fatal!`] on `EINVAL` or unexpected errors.
    #[tracing::instrument(level = "info")]
    pub fn unmount_filesystems() {
        debug!("syncing filesystems");
        sync();
        debug!("umounting filesystems");
        // Unmount in reverse order of mounting
        const MOUNTS_TO_UNMOUNT: [&str; 5] = ["/run", "/tmp", "/sys/fs/cgroup", "/sys", "/proc"];

        for mount_point in MOUNTS_TO_UNMOUNT {
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
        info!("starting init system");
        debug!("registering signal handlers");

        // signals to handle in init system
        let mut sigterm = signal(SignalKind::terminate()).unwrap();

        // benign signals to forward to main process
        // NOTE: we intentionally do not handle SIGCHLD yet.
        // If the test is leaking processes that is a failure criteria we will catch after the main process exits.
        let mut sighup = signal(SignalKind::hangup()).unwrap();
        let mut siguser1 = signal(SignalKind::user_defined1()).unwrap();
        let mut siguser2 = signal(SignalKind::user_defined2()).unwrap();
        let mut sigwindow = signal(SignalKind::window_change()).unwrap();

        // signals which represent failure if received, but which should still be forwarded to main process
        let mut sigint = signal(SignalKind::interrupt()).unwrap();
        let mut sigalarm = signal(SignalKind::alarm()).unwrap();
        let mut sigpipe = signal(SignalKind::pipe()).unwrap();
        let mut sigquit = signal(SignalKind::quit()).unwrap();

        debug!("signal handlers registered");

        // Mount essential filesystems
        tokio::task::spawn_blocking(Self::mount_essential_filesystems)
            .await
            .unwrap()
            .unwrap();

        // Spawn the main process
        let (mut console, mut child) = InitSystem::spawn_main_process().await;

        let pid = Pid::from_raw(child.id().unwrap() as i32);

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
                    match console.flush().await {
                        Ok(_) => {},
                        Err(e) => {
                            error!("failed to flush console: {e}");
                            success = false;
                        },
                    }
                    break;
                }
                _ = sigterm.recv() => {
                    debug!("received SIGTERM");
                    success = false;
                    nix::sys::signal::kill(pid, nix::sys::signal::SIGTERM).unwrap();
                }
                _ = sigint.recv() => {
                    warn!("forwarding SIGINT");
                    success = false;
                    nix::sys::signal::kill(pid, nix::sys::signal::SIGINT).unwrap();
                }
                _ = sigalarm.recv() => {
                    warn!("forwarding ALARM");
                    success = false;
                    nix::sys::signal::kill(pid, nix::sys::signal::SIGUSR2).unwrap();
                }
                _ = sigpipe.recv() => {
                    warn!("forwarding PIPE");
                    success = false;
                    nix::sys::signal::kill(pid, nix::sys::signal::SIGPIPE).unwrap();
                }
                _ = sigquit.recv() => {
                    warn!("forwarding QUIT");
                    success = false;
                    nix::sys::signal::kill(pid, nix::sys::signal::SIGQUIT).unwrap();
                }
                _ = sighup.recv() => {
                    debug!("forwarding SIGHUP");
                    nix::sys::signal::kill(pid, nix::sys::signal::SIGHUP).unwrap();
                }
                _ = siguser1.recv() => {
                    debug!("forwarding SIGUSR1");
                    nix::sys::signal::kill(pid, nix::sys::signal::SIGUSR1).unwrap();
                }
                _ = siguser2.recv() => {
                    debug!("forwarding SIGUSR2");
                    nix::sys::signal::kill(pid, nix::sys::signal::SIGUSR2).unwrap();
                }
                _ = sigwindow.recv() => {
                    trace!("forwarding WINDOW");
                    nix::sys::signal::kill(pid, nix::sys::signal::SIGWINCH).unwrap();
                }
            }
        }
        InitSystem::shutdown_system(success).await
    }

    /// Lists all direct child processes of init (PPID == 1) by scanning `/proc`.
    pub async fn list_child_processes() -> Vec<Pid> {
        let mut child_pids = tokio::fs::read_dir("/proc").await.unwrap();
        let mut children = vec![];
        while let Some(process) = child_pids.next_entry().await.unwrap() {
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