//! Init system orchestrator.
//!
//! This module ties together the [`mount`](crate::mount),
//! [`child`](crate::child), and [`signal`](crate::signal) subsystems
//! into the main init system lifecycle:
//!
//! 1. Register signal handlers ([`SignalSet`](crate::signal::SignalSet)).
//! 2. Mount essential filesystems.
//! 3. Spawn the test process.
//! 4. Enter the event loop — forward signals and wait for exit.
//! 5. Shut down cleanly (terminate children, unmount, power off / abort).
//!
//! Each phase delegates to a focused module, so the orchestrator itself
//! requires only local reasoning about sequencing.

use std::convert::Infallible;

use nix::sys::reboot::{RebootMode, reboot};
use nix::unistd::Pid;
use tracing::{debug, error, info};

use crate::child;
use crate::mount;
use crate::signal::{SignalPolicy, SignalSet, SIGNAL_TABLE};

/// Minimal init system for running tests inside a cloud-hypervisor VM.
///
/// This unit struct groups the top-level orchestration methods.  It is
/// intended to run as PID 1 and delegates filesystem mounting, process
/// lifecycle management, signal forwarding, and clean shutdown to the
/// [`mount`], [`child`], and [`signal`] modules.
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
        info!("starting init system");

        // ── Signal registration ──────────────────────────────────
        debug!("registering signal handlers");
        let mut signals = SignalSet::register(SIGNAL_TABLE);
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
            tokio::select! {
                result = test_child.wait() => {
                    match result {
                        Ok(status) if status.success() => {
                            debug!("main process exited successfully with status {status}");
                        }
                        Ok(status) => {
                            error!("main process exited with failure status {status}");
                            success = false;
                        }
                        Err(e) => {
                            error!("main process error: {e}");
                            success = false;
                        }
                    }
                    break;
                }
                spec = signals.recv() => {
                    match spec.policy {
                        SignalPolicy::Failure => {
                            debug!("received failure signal {}, forwarding and marking failed", spec.label);
                            success = false;
                        }
                        SignalPolicy::Benign => {
                            debug!("forwarding benign signal {}", spec.label);
                        }
                    }
                    child::forward_signal(pid, spec.signal);
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