//! Filesystem mount and unmount operations for the init system.
//!
//! This module manages the essential virtual filesystems (`/proc`, `/sys`,
//! `/tmp`, `/run`, `/sys/fs/cgroup`) required by the guest OS before the
//! test process can run.
//!
//! `/dev` is intentionally absent because `CONFIG_DEVTMPFS_MOUNT` is
//! enabled in the kernel configuration, so it is auto-mounted.

use nix::errno::Errno;
use nix::mount::{MntFlags, MsFlags, mount};
use nix::unistd::sync;
use tokio::time::Duration;
use tracing::{debug, warn};

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

/// Maximum number of `EBUSY` retries per mount point before giving up.
///
/// At 1 ms per retry this gives each mount point up to ~1 second to
/// become idle — more than enough for well-behaved tests.
const UMOUNT_MAX_EBUSY_RETRIES: u32 = 1_000;

/// Mounts the essential virtual filesystems required by the guest OS.
///
/// Iterates over [`ESSENTIAL_MOUNTS`] and mounts each entry with the
/// security flags `nosuid`, `noexec`, `nodev`.  `/dev` is not mounted
/// here because `CONFIG_DEVTMPFS_MOUNT` is enabled in the kernel
/// configuration.
///
/// Calls [`fatal!`] (which aborts the process) if any mount fails.
pub fn mount_essential_filesystems() {
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
}

/// Unmounts all [`ESSENTIAL_MOUNTS`] in reverse order.
///
/// Syncs the filesystem before and after each unmount.  Uses
/// `MNT_DETACH` to handle busy mount points, retrying on `EBUSY` up
/// to [`UMOUNT_MAX_EBUSY_RETRIES`] times per mount point.
/// Calls [`fatal!`] on `EINVAL`, unexpected errors, or if retries are
/// exhausted.
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
        let mut attempts: u32 = 0;
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
                    attempts += 1;
                    if attempts >= UMOUNT_MAX_EBUSY_RETRIES {
                        fatal!(
                            "{mount_point} still busy after {attempts} retries; \
                             a leaked process is likely holding a file descriptor open"
                        );
                    }
                    if attempts.is_multiple_of(100) {
                        warn!(
                            "{mount_point} still busy after {attempts} retries"
                        );
                    }
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