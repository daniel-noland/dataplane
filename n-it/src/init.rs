//! Init system orchestrator.
//!
//! This module ties together the [`mount`](crate::mount) and
//! [`child`](crate::child) subsystems into the main init system
//! lifecycle:
//!
//! 1. Register signal handlers.
//! 2. Mount essential filesystems.
//! 3. Spawn the test process.
//! 4. Enter the event loop — forward signals and wait for exit.
//! 5. Shut down cleanly (terminate children, unmount, power off / abort).
//!
//! Each phase delegates to a focused module where possible, so the
//! orchestrator itself requires only local reasoning about sequencing.

use std::convert::Infallible;

use nix::sys::reboot::{RebootMode, reboot};
use nix::sys::signal::Signal;
use nix::unistd::Pid;
use tokio::signal::unix::{SignalKind, signal};
use tracing::{debug, error, info, trace, warn};

use crate::child;
use crate::mount;

/// Minimal init system for running tests inside a cloud-hypervisor VM.
///
/// This unit struct groups the top-level orchestration methods.  It is
/// intended to run as PID 1 and delegates filesystem mounting, process
/// lifecycle management, and clean shutdown to the [`mount`] and
/// [`child`] modules.
#[derive(Debug)]
#[non_exhaustive]
pub struct InitSystem;

impl InitSystem {
    /// Main entry point for the init system.
    ///
    /// Registers signal handlers, mounts filesystems, spawns the test
    /// process, and enters the main event loop.  The event loop forwards
    /// signals to the test process and waits for it to exit, then
    /// initiates shutdown.
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

        // ── Filesystem setup ─────────────────────────────────────
        match tokio::task::spawn_blocking(mount::mount_essential_filesystems).await {
            Ok(()) => {}
            Err(e) => fatal!("mount filesystem task panicked: {e}"),
        }

        // ── Spawn test process ───────────────────────────────────
        let mut test_child = child::spawn_main_process().await;
        let pid = match test_child.id() {
            Some(id) => Pid::from_raw(id as i32),
            None => fatal!("unable to determine PID of spawned test process"),
        };

        let mut success = true;

        // ── Event loop ───────────────────────────────────────────
        loop {
            // any non-terminating exit of this loop should cause us to reap orphaned child processes
            tokio::select! {
                // Main process completion
                result = test_child.wait() => {
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
                    child::forward_signal(pid, Signal::SIGTERM);
                }
                _ = sigint.recv() => {
                    warn!("forwarding SIGINT");
                    success = false;
                    child::forward_signal(pid, Signal::SIGINT);
                }
                _ = sigalarm.recv() => {
                    warn!("forwarding SIGALRM");
                    success = false;
                    child::forward_signal(pid, Signal::SIGALRM);
                }
                _ = sigpipe.recv() => {
                    warn!("forwarding PIPE");
                    success = false;
                    child::forward_signal(pid, Signal::SIGPIPE);
                }
                _ = sigquit.recv() => {
                    warn!("forwarding QUIT");
                    success = false;
                    child::forward_signal(pid, Signal::SIGQUIT);
                }
                _ = sighup.recv() => {
                    debug!("forwarding SIGHUP");
                    child::forward_signal(pid, Signal::SIGHUP);
                }
                _ = siguser1.recv() => {
                    debug!("forwarding SIGUSR1");
                    child::forward_signal(pid, Signal::SIGUSR1);
                }
                _ = siguser2.recv() => {
                    debug!("forwarding SIGUSR2");
                    child::forward_signal(pid, Signal::SIGUSR2);
                }
                _ = sigwindow.recv() => {
                    trace!("forwarding WINDOW");
                    child::forward_signal(pid, Signal::SIGWINCH);
                }
            }
        }

        Self::shutdown_system(success).await
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
    async fn shutdown_system(success: bool) -> Infallible {
        info!("beginning system shutdown");

        // Terminate all child processes; leaked processes downgrade success.
        let success = child::terminate_remaining_processes().await.is_none() && success;

        // Final sync, unmount, and power off / abort.
        match tokio::task::spawn_blocking(move || {
            mount::unmount_filesystems();
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
                // Normally unreachable — the blocking task either powers off
                // or aborts.  Use fatal! to ensure stdio is flushed.
                fatal!("unreachable code?");
            }
            Err(err) => {
                fatal!("failed to shutdown system: {err}");
            }
        }
    }
}