//! Process lifecycle management for the init system.
//!
//! This module handles spawning the test binary, reaping orphaned processes,
//! forwarding signals, and gracefully terminating remaining children during
//! shutdown.

use std::os::unix::io::{FromRawFd, IntoRawFd};
use std::process::Stdio;

use n_vm_protocol::{ENV_IN_VM, ENV_MARKER_VALUE, VsockChannel};
use nix::errno::Errno;
use nix::sys::signal::{Signal, kill};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::Pid;
use tokio::process::{Child, Command};
use tokio::time::{Duration, sleep};
use tokio_vsock::VMADDR_CID_HOST;
use tracing::{debug, error, trace, warn};

/// Spawns the test binary as the main child process.
///
/// Reads the binary path and test name from the kernel command line
/// arguments (passed via `init=`), sets `IN_VM=YES` so the `#[in_vm]`
/// macro executes the test body directly, and redirects stdout/stderr to
/// dedicated vsock streams ([`VsockChannel::TEST_STDOUT`] and
/// [`VsockChannel::TEST_STDERR`]).
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
    let stdout_addr = vsock::VsockAddr::new(VMADDR_CID_HOST, VsockChannel::TEST_STDOUT.port);
    let stdout_stream = vsock::VsockStream::connect(&stdout_addr)
        .unwrap_or_else(|e| fatal!("failed to connect stdout vsock: {e}"));

    let stderr_addr = vsock::VsockAddr::new(VMADDR_CID_HOST, VsockChannel::TEST_STDERR.port);
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
/// Unlike [`send_signal_to_all_processes`], this targets a single PID and
/// treats `ESRCH` (no such process) as a non-fatal condition — the child
/// may have exited between the time the signal was received and the time
/// we attempt to forward it.
pub fn forward_signal(pid: Pid, sig: Signal) {
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

/// Maximum number of SIGTERM rounds before giving up.
const MAX_SIGTERM_ATTEMPTS: u8 = 50;

/// Terminates all remaining child processes with SIGTERM.
///
/// Sends up to [`MAX_SIGTERM_ATTEMPTS`] rounds of SIGTERM (with 10 ms
/// sleeps between rounds), reaping exited processes after each round.
///
/// Returns `None` if no child processes were remaining, or `Some(())`
/// if processes were found (whether or not they all terminated
/// successfully).
#[tracing::instrument(level = "info")]
pub async fn terminate_remaining_processes() -> Option<()> {
    if list_child_processes().await.is_empty() {
        trace!("no child processes remaining");
        return None;
    }
    if let Some(()) = reap() {
        warn!("test seems to be leaking processes");
    }
    // Send SIGTERM to all processes
    let mut sigs: u8 = 0;
    warn!("sending SIGTERM to all remaining processes");
    while sigs <= MAX_SIGTERM_ATTEMPTS
        && let Some(()) = send_signal_to_all_processes(Signal::SIGTERM)
    {
        sigs += 1;
        sleep(Duration::from_millis(10)).await;
        if let Some(()) = reap() {
            error!("test is leaking processes");
        }
        if list_child_processes().await.is_empty() {
            debug!("no child processes remaining");
            return Some(());
        }
    }
    error!("maximum SIGTERM attempts reached: test did not shut down correctly");
    return Some(());
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
            let pid = i32::try_from(pid)
                .unwrap_or_else(|_| fatal!("child pid {pid} overflows i32"));
            children.push(Pid::from_raw(pid));
        }
    }
    children
}