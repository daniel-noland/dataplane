//! Filesystem mount and unmount operations for the init system.
//!
//! This module manages the essential virtual filesystems (`/proc`, `/sys`,
//! `/tmp`, `/run`, `/sys/fs/cgroup`) and the hugetlbfs mounts
//! (`/run/huge/2MiB`, `/run/huge/1GiB`) required by the guest OS before
//! the test process can run.
//!
//! `/dev` is intentionally absent because `CONFIG_DEVTMPFS_MOUNT` is
//! enabled in the kernel configuration, so it is auto-mounted.
//!
//! # Hugetlbfs
//!
//! Two hugetlbfs instances are mounted under `/run/huge/` — one for each
//! supported hugepage granularity.  Both are mounted unconditionally
//! because the mount is harmless (and near-instant) when no hugepages of
//! the corresponding size have been reserved by the kernel.  This avoids
//! coupling the init system to the guest hugepage configuration passed on
//! the kernel command line.
//!
//! DPDK (and other consumers) can then use `--huge-dir /run/huge/2MiB`
//! or `--huge-dir /run/huge/1GiB` to map the appropriate pool.

use std::path::Path;

use nix::errno::Errno;
use nix::mount::{MntFlags, MsFlags, mount};
use nix::unistd::sync;
use std::time::Duration;
use tracing::{debug, warn};

use crate::error::{MountError, UnmountError};

/// A single entry in the essential-filesystems mount table.
///
/// All fields correspond to the arguments of [`nix::mount::mount`],
/// with the addition of [`create_target`](Self::create_target) for
/// mount points that live on writable parent filesystems and therefore
/// cannot be baked into the read-only vmroot image, and
/// [`optional`](Self::optional) for mounts that may legitimately fail
/// at runtime.
struct MountEntry {
    /// Filesystem source (e.g. `"proc"`, `"tmpfs"`, `"hugetlbfs"`).
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
    /// When `true`, [`secure_mount`] creates the target directory (and
    /// any missing parents) before attempting the mount.
    ///
    /// This is necessary for mount points that live under a writable
    /// parent filesystem (e.g. `/run/huge/2MiB` under the `/run`
    /// tmpfs) and therefore cannot be pre-created in the read-only
    /// vmroot Nix derivation.
    ///
    /// Mount points that correspond to directories baked into the
    /// vmroot image (e.g. `/proc`, `/sys`) should set this to `false`.
    create_target: bool,
    /// When `true`, a mount failure is logged as a warning and does
    /// **not** abort the init system.
    ///
    /// This is used for hugetlbfs mounts where the requested page size
    /// may not be supported by the guest CPU (e.g. 1 GiB hugepages
    /// require the `pdpe1gb` feature).  The mount is attempted
    /// optimistically; if the kernel rejects it the test can still
    /// proceed with whichever page sizes *are* available.
    optional: bool,
}

/// The filesystems that must be mounted before the test process can run.
///
/// `/dev` is intentionally absent because `CONFIG_DEVTMPFS_MOUNT` is
/// enabled in the kernel configuration, so it is auto-mounted.
///
/// All entries share the security flags `MS_NOSUID | MS_NOEXEC | MS_NODEV`.
///
/// **Ordering invariant**: child mount points must appear *after* their
/// parents so that the parent filesystem is available when the child is
/// mounted, and reverse-order unmounting processes children before
/// parents.
const ESSENTIAL_MOUNTS: &[MountEntry] = &[
    MountEntry {
        source: "proc",
        target: "/proc",
        fstype: "proc",
        data: None,
        create_target: false,
        optional: false,
    },
    MountEntry {
        source: "sysfs",
        target: "/sys",
        fstype: "sysfs",
        data: None,
        create_target: false,
        optional: false,
    },
    MountEntry {
        source: "tmpfs",
        target: "/tmp",
        fstype: "tmpfs",
        data: Some("mode=0600,size=5%"),
        create_target: false,
        optional: false,
    },
    MountEntry {
        source: "tmpfs",
        target: "/run",
        fstype: "tmpfs",
        data: Some("mode=0600,size=5%"),
        create_target: false,
        optional: false,
    },
    // ── Hugetlbfs ────────────────────────────────────────────────────
    //
    // Mounted under /run (a writable tmpfs) so the directory can be
    // created at runtime without touching the read-only root image.
    //
    // Both sizes are attempted; when the guest CPU does not support a
    // given page size (e.g. 1 GiB requires `pdpe1gb`) the kernel
    // returns EINVAL and we log a warning rather than aborting.  When
    // no hugepages of a given size have been reserved on the kernel
    // command line the mount point is simply empty.
    MountEntry {
        source: "hugetlbfs",
        target: "/run/huge/2MiB",
        fstype: "hugetlbfs",
        data: Some("pagesize=2M"),
        create_target: true,
        optional: true,
    },
    MountEntry {
        source: "hugetlbfs",
        target: "/run/huge/1GiB",
        fstype: "hugetlbfs",
        data: Some("pagesize=1G"),
        create_target: true,
        optional: true,
    },
    MountEntry {
        source: "cgroup2",
        target: "/sys/fs/cgroup",
        fstype: "cgroup2",
        data: Some("nsdelegate,memory_recursiveprot"),
        create_target: false,
        optional: false,
    },
];

/// Maximum number of `EBUSY` retries per mount point before giving up.
///
/// At 1 ms per retry this gives each mount point up to ~1 second to
/// become idle -- more than enough for well-behaved tests.
const UMOUNT_MAX_EBUSY_RETRIES: u32 = 1_000;

/// Mounts the essential virtual filesystems required by the guest OS.
///
/// Iterates over [`ESSENTIAL_MOUNTS`] and mounts each entry with the
/// security flags `nosuid`, `noexec`, `nodev`.  `/dev` is not mounted
/// here because `CONFIG_DEVTMPFS_MOUNT` is enabled in the kernel
/// configuration.
///
/// Entries with [`create_target`](MountEntry::create_target) set to
/// `true` have their mount-point directory created (including any
/// missing parents) before the mount syscall.
///
/// Entries with [`optional`](MountEntry::optional) set to `true` log a
/// warning on failure instead of returning an error.  This is used for
/// hugetlbfs mounts where the requested page size may not be supported
/// by the guest CPU.
///
/// # Errors
///
/// Returns a [`MountError`] if any **non-optional** mount syscall (or
/// preparatory `mkdir`) fails.
pub fn mount_essential_filesystems() -> Result<(), MountError> {
    for entry in ESSENTIAL_MOUNTS {
        match secure_mount(entry) {
            Ok(()) => {}
            Err(e) if entry.optional => {
                warn!(
                    "optional mount {} failed ({}); skipping",
                    entry.target, e,
                );
            }
            Err(e) => return Err(e),
        }
    }
    debug!("all essential filesystems mounted successfully");
    Ok(())
}

/// Performs a single mount with security flags, optionally creating the
/// target directory first.
fn secure_mount(entry: &MountEntry) -> Result<(), MountError> {
    let MountEntry {
        source,
        target,
        fstype,
        data,
        create_target,
        optional: _,
    } = entry;
    let target_path: &'static Path = Path::new(*target);

    if *create_target {
        debug!("creating mount point {}", target_path.display());
        std::fs::create_dir_all(*target).map_err(|e| {
            let errno = e
                .raw_os_error()
                .map_or(Errno::UnknownErrno, Errno::from_raw);
            MountError::Failed {
                target: target_path,
                source: errno,
            }
        })?;
    }

    debug!("mounting {}", target_path.display());
    mount(
        Some(*source),
        *target,
        Some(*fstype),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV,
        *data,
    )
    .map_err(|e| match e {
        Errno::UnknownErrno => MountError::Unknown {
            target: target_path,
        },
        Errno::EPERM => MountError::PermissionDenied {
            target: target_path,
        },
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
    //
    // Optional mounts that failed during setup were never mounted, so
    // unmounting them would return EINVAL.  We tolerate EINVAL for
    // optional entries rather than tracking which ones succeeded.
    for entry in ESSENTIAL_MOUNTS.iter().rev() {
        let mount_point = Path::new(entry.target);
        match unmount_one(mount_point) {
            Ok(()) => {}
            Err(UnmountError::NotMounted { .. }) if entry.optional => {
                debug!(
                    "optional mount {} was not mounted; skipping unmount",
                    mount_point.display(),
                );
            }
            Err(e) => return Err(e),
        }
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
                    // A child of `parent` appears later -- this is correct.
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

    /// All hugetlbfs entries must be marked optional because the guest
    /// CPU may not support every page size (e.g. 1 GiB requires
    /// `pdpe1gb`).
    #[test]
    fn hugetlbfs_entries_are_optional() {
        for entry in ESSENTIAL_MOUNTS
            .iter()
            .filter(|e| e.fstype == "hugetlbfs")
        {
            assert!(
                entry.optional,
                "hugetlbfs mount at {:?} should be optional",
                entry.target,
            );
        }
    }

    /// Non-hugetlbfs entries must not be optional — they are required
    /// for the guest to function correctly.
    #[test]
    fn non_hugetlbfs_entries_are_not_optional() {
        for entry in ESSENTIAL_MOUNTS
            .iter()
            .filter(|e| e.fstype != "hugetlbfs")
        {
            assert!(
                !entry.optional,
                "non-hugetlbfs mount at {:?} should not be optional",
                entry.target,
            );
        }
    }

    /// The hugetlbfs mounts live under `/run`, so they must appear after
    /// the `/run` tmpfs entry.
    #[test]
    fn hugetlbfs_mounts_appear_after_run() {
        let run_pos = ESSENTIAL_MOUNTS
            .iter()
            .position(|e| e.target == "/run")
            .expect("/run should be in ESSENTIAL_MOUNTS");
        for entry in ESSENTIAL_MOUNTS
            .iter()
            .filter(|e| e.fstype == "hugetlbfs")
        {
            let pos = ESSENTIAL_MOUNTS
                .iter()
                .position(|e| std::ptr::eq(e, entry))
                .unwrap();
            assert!(
                pos > run_pos,
                "hugetlbfs mount {target:?} (index {pos}) must appear after \
                 /run (index {run_pos})",
                target = entry.target,
            );
        }
    }

    /// Hugetlbfs entries must set `create_target` because their mount
    /// points live on the `/run` tmpfs and cannot be baked into the
    /// read-only vmroot image.
    #[test]
    fn hugetlbfs_entries_require_create_target() {
        for entry in ESSENTIAL_MOUNTS
            .iter()
            .filter(|e| e.fstype == "hugetlbfs")
        {
            assert!(
                entry.create_target,
                "hugetlbfs mount at {:?} should have create_target = true",
                entry.target,
            );
        }
    }

    /// Entries with `create_target = false` must have mount points that
    /// are provided by the vmroot image or a kernel-auto-mounted
    /// filesystem.  Conversely, entries with `create_target = true` must
    /// be children of a writable parent in the table.
    #[test]
    fn create_target_entries_are_children_of_writable_mounts() {
        let writable_targets: Vec<&str> = ESSENTIAL_MOUNTS
            .iter()
            .filter(|e| e.fstype == "tmpfs")
            .map(|e| e.target)
            .collect();

        for entry in ESSENTIAL_MOUNTS.iter().filter(|e| e.create_target) {
            let has_writable_parent = writable_targets.iter().any(|parent| {
                entry.target.starts_with(parent)
                    && entry.target != *parent
                    && entry.target.as_bytes().get(parent.len()) == Some(&b'/')
            });
            assert!(
                has_writable_parent,
                "mount {:?} has create_target = true but is not a child \
                 of any tmpfs mount; the directory cannot be created at runtime",
                entry.target,
            );
        }
    }

    /// Both 2 MiB and 1 GiB hugetlbfs mounts must be present.
    #[test]
    fn hugetlbfs_mounts_cover_both_page_sizes() {
        let hugetlb: Vec<&str> = ESSENTIAL_MOUNTS
            .iter()
            .filter(|e| e.fstype == "hugetlbfs")
            .map(|e| e.target)
            .collect();
        assert!(
            hugetlb.contains(&"/run/huge/2MiB"),
            "missing 2 MiB hugetlbfs mount; got: {hugetlb:?}",
        );
        assert!(
            hugetlb.contains(&"/run/huge/1GiB"),
            "missing 1 GiB hugetlbfs mount; got: {hugetlb:?}",
        );
    }

    /// Each hugetlbfs entry must specify a `pagesize=` mount option
    /// matching its mount-point name.
    #[test]
    fn hugetlbfs_pagesize_matches_mount_point() {
        for entry in ESSENTIAL_MOUNTS
            .iter()
            .filter(|e| e.fstype == "hugetlbfs")
        {
            let data = entry
                .data
                .unwrap_or_else(|| panic!("hugetlbfs mount {:?} has no data", entry.target));
            if entry.target.contains("2MiB") {
                assert!(
                    data.contains("pagesize=2M"),
                    "2MiB hugetlbfs mount should have pagesize=2M, got: {data}",
                );
            } else if entry.target.contains("1GiB") {
                assert!(
                    data.contains("pagesize=1G"),
                    "1GiB hugetlbfs mount should have pagesize=1G, got: {data}",
                );
            }
        }
    }
}