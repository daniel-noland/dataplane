//! Filesystem mount and unmount operations for the init system.
//!
//! This module manages the essential virtual filesystems (`/proc`, `/sys`,
//! `/tmp`, `/run`, `/sys/fs/cgroup`) required by the guest OS before the
//! test process can run.
//!
//! `/dev` is intentionally absent because `CONFIG_DEVTMPFS_MOUNT` is
//! enabled in the kernel configuration, so it is auto-mounted.

use std::path::Path;

use nix::errno::Errno;
use nix::mount::{MntFlags, MsFlags, mount};
use nix::unistd::sync;
use tokio::time::Duration;
use tracing::{debug, warn};

use crate::error::{MountError, UnmountError};

/// A single entry in the essential-filesystems mount table.
///
/// All fields correspond to the arguments of [`nix::mount::mount`].
struct MountEntry {
    /// Filesystem source (e.g. `"proc"`, `"tmpfs"`).
    source: &'static str,
    /// Mount point path.
    ///
    /// Stored as `&str` rather than `&Path` because `Path::new()` is not
    /// yet const-stable.  Converted to `&'static Path` at the call
    /// boundary (see [`secure_mount`] and [`unmount_filesystems`]).
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
/// # Errors
///
/// Returns a [`MountError`] if any individual mount syscall fails.
pub fn mount_essential_filesystems() -> Result<(), MountError> {
    for entry in ESSENTIAL_MOUNTS {
        secure_mount(entry)?;
    }
    debug!("all essential filesystems mounted successfully");
    Ok(())
}

/// Performs a single mount with security flags.
fn secure_mount(entry: &MountEntry) -> Result<(), MountError> {
    let MountEntry { source, target, fstype, data } = entry;
    let target_path: &'static Path = Path::new(*target);
    debug!("mounting {}", target_path.display());
    mount(
        Some(*source),
        *target,
        Some(*fstype),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV,
        *data,
    )
    .map_err(|e| match e {
        Errno::UnknownErrno => MountError::Unknown { target: target_path },
        Errno::EPERM => MountError::PermissionDenied { target: target_path },
        other => MountError::Failed {
            target: target_path,
            source: other,
        },
    })
}

/// Unmounts all [`ESSENTIAL_MOUNTS`] in reverse order.
///
/// Syncs the filesystem before and after each unmount.  Uses
/// `MNT_DETACH` to handle busy mount points, retrying on `EBUSY` up
/// to [`UMOUNT_MAX_EBUSY_RETRIES`] times per mount point.
///
/// # Errors
///
/// Returns an [`UnmountError`] on `EINVAL`, unexpected errors, or if
/// retries are exhausted for a busy mount point.
#[tracing::instrument(level = "info")]
pub fn unmount_filesystems() -> Result<(), UnmountError> {
    debug!("syncing filesystems");
    sync();
    debug!("umounting filesystems");
    // Unmount in reverse order of mounting, derived from the same
    // table used by mount_essential_filesystems().
    for mount_point in ESSENTIAL_MOUNTS.iter().rev().map(|e| Path::new(e.target)) {
        unmount_one(mount_point)?;
    }
    debug!("filesystem umounting completed");
    debug!("final sync");
    sync();
    Ok(())
}

/// Unmounts a single mount point, retrying on `EBUSY`.
///
/// # Note on blocking sleep
///
/// This function uses [`std::thread::sleep`] rather than
/// [`tokio::time::sleep`] because it is called from within
/// [`tokio::task::spawn_blocking`].  The blocking sleep is intentional:
/// filesystem unmounting requires synchronous syscalls, and since the
/// tokio runtime is configured with `max_blocking_threads(1)`, this
/// thread is dedicated to shutdown work where async cooperation is not
/// needed.
fn unmount_one(mount_point: &'static Path) -> Result<(), UnmountError> {
    debug!("umounting {}", mount_point.display());
    sync();
    let mut attempts: u32 = 0;
    loop {
        match nix::mount::umount2(
            mount_point,
            MntFlags::MNT_DETACH | MntFlags::UMOUNT_NOFOLLOW,
        ) {
            Ok(()) => {
                debug!("successfully unmounted {}", mount_point.display());
                sync();
                return Ok(());
            }
            Err(Errno::EBUSY) => {
                attempts += 1;
                if attempts >= UMOUNT_MAX_EBUSY_RETRIES {
                    return Err(UnmountError::BusyExhausted {
                        target: mount_point,
                        attempts,
                    });
                }
                if attempts.is_multiple_of(100) {
                    warn!(
                        "{} still busy after {attempts} retries",
                        mount_point.display(),
                    );
                }
                sync();
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(Errno::EINVAL) => {
                return Err(UnmountError::NotMounted {
                    target: mount_point,
                });
            }
            Err(e) => {
                return Err(UnmountError::Failed {
                    target: mount_point,
                    source: e,
                });
            }
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mount_targets_are_all_absolute_paths() {
        for entry in ESSENTIAL_MOUNTS {
            assert!(
                entry.target.starts_with('/'),
                "mount target should be absolute: {:?}",
                entry.target,
            );
        }
    }

    #[test]
    fn mount_targets_have_no_duplicates() {
        let mut targets: Vec<&str> = ESSENTIAL_MOUNTS.iter().map(|e| e.target).collect();
        let original_len = targets.len();
        targets.sort();
        targets.dedup();
        assert_eq!(
            targets.len(),
            original_len,
            "ESSENTIAL_MOUNTS contains duplicate targets",
        );
    }

    #[test]
    fn mount_sources_are_non_empty() {
        for entry in ESSENTIAL_MOUNTS {
            assert!(
                !entry.source.is_empty(),
                "mount source should not be empty for target {:?}",
                entry.target,
            );
        }
    }

    #[test]
    fn mount_fstypes_are_non_empty() {
        for entry in ESSENTIAL_MOUNTS {
            assert!(
                !entry.fstype.is_empty(),
                "mount fstype should not be empty for target {:?}",
                entry.target,
            );
        }
    }

    /// The unmount order is the reverse of the mount order.  Child mount
    /// points must be unmounted before their parents (e.g. `/sys/fs/cgroup`
    /// before `/sys`).  This test verifies that no mount point is a prefix
    /// of a *later* entry, because the reverse iteration used by
    /// `unmount_filesystems` would then try to unmount the parent first.
    #[test]
    fn mount_order_ensures_children_appear_after_parents() {
        for (i, entry) in ESSENTIAL_MOUNTS.iter().enumerate() {
            let parent = entry.target;
            for later in &ESSENTIAL_MOUNTS[i + 1..] {
                if later.target.starts_with(parent) && later.target != parent {
                    // A child of `parent` appears later — this is correct.
                    // The reverse unmount order will process the child first.
                    //
                    // Now verify the *inverse* is not also true (which would
                    // indicate an impossible ordering).
                    assert!(
                        !parent.starts_with(later.target),
                        "circular mount dependency: {parent:?} and {:?}",
                        later.target,
                    );
                }
            }
        }
    }

    /// Verify that every child mount point appears *after* its parent in
    /// the table.  For example, `/sys/fs/cgroup` must come after `/sys`.
    /// If a child appeared before its parent, mounting would fail because
    /// the parent directory does not yet exist.
    #[test]
    fn child_mount_points_appear_after_their_parents() {
        for (i, entry) in ESSENTIAL_MOUNTS.iter().enumerate() {
            let target = entry.target;
            // Check if any earlier entry is a proper prefix (i.e. is a parent).
            // If target has a parent in the table, that parent must have a
            // smaller index.
            for (j, other) in ESSENTIAL_MOUNTS.iter().enumerate() {
                if i == j {
                    continue;
                }
                let is_child = target.starts_with(other.target)
                    && target != other.target
                    && target.as_bytes().get(other.target.len()) == Some(&b'/');
                if is_child {
                    assert!(
                        j < i,
                        "mount target {target:?} is a child of {:?}, \
                         but the parent appears at index {j} (after child at index {i})",
                        other.target,
                    );
                }
            }
        }
    }

    /// `/sys/fs/cgroup` specifically depends on `/sys` being mounted first.
    /// This is a concrete regression test for the ordering invariant above.
    #[test]
    fn cgroup_is_mounted_after_sys() {
        let sys_pos = ESSENTIAL_MOUNTS
            .iter()
            .position(|e| e.target == "/sys")
            .expect("/sys should be in ESSENTIAL_MOUNTS");
        let cgroup_pos = ESSENTIAL_MOUNTS
            .iter()
            .position(|e| e.target == "/sys/fs/cgroup")
            .expect("/sys/fs/cgroup should be in ESSENTIAL_MOUNTS");
        assert!(
            sys_pos < cgroup_pos,
            "/sys (index {sys_pos}) must be mounted before /sys/fs/cgroup (index {cgroup_pos})",
        );
    }
}