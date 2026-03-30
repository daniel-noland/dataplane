// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! VM lifecycle management for the container tier.
//!
//! # Error handling
//!
//! Functions that can fail return [`Result<_, VmError>`].  The
//! [`TestVm::collect`] phase is intentionally infallible -- individual
//! subsystem failures are recorded as degraded output (e.g.
//! `"!!!...UNAVAILABLE...!!!"`) rather than propagated, because the primary
//! goal is to give the developer as much diagnostic information as
//! possible even when things go wrong.
//!
//! This module handles launching virtiofsd, delegating hypervisor-specific
//! VM setup to a [`HypervisorBackend`], collecting output from all
//! subsystems, and returning a unified [`VmTestOutput`].
//!
//! Test process stdout and stderr are forwarded from the VM guest to the
//! container tier via dedicated [`VsockChannel`]s, giving the host clean
//! separation of the two channels.  The hypervisor's virtio-console is
//! expected to be disabled -- all test output travels over vsock.
//!
//! # Lifecycle
//!
//! The [`TestVm`] struct owns every long-lived resource (child processes,
//! background tasks, backend controller) and exposes a two-phase API:
//!
//! 1. [`TestVm::launch`] -- prepares the environment (virtiofsd, vsock
//!    listeners, hypervisor backend) and boots the VM.
//! 2. [`TestVm::collect`] -- waits for the test to finish, gathers output
//!    from all subsystems, and performs a clean shutdown.
//!
//! The convenience function [`run_in_vm`] wraps both phases for the
//! `#[in_vm]` macro.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use n_vm_protocol::{
    INIT_BINARY_PATH, KERNEL_CONSOLE_SOCKET_PATH, VIRTIOFS_ROOT_TAG, VIRTIOFSD_BINARY_PATH,
    VIRTIOFSD_SOCKET_PATH, VM_ROOT_SHARE_PATH, VsockAllocation, VsockChannel, VsockCid,
    VsockPort,
};
use rand::RngExt;
use tokio::io::AsyncReadExt;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use crate::abort_on_drop::AbortOnDrop;
use crate::backend::{HypervisorBackend, HypervisorVerdict};
use crate::config;
use crate::error::VmError;

// ── Constants ────────────────────────────────────────────────────────

/// Maximum number of poll iterations before giving up on a socket.
const SOCKET_POLL_MAX_ATTEMPTS: u32 = 100;

/// Interval between socket existence checks.
const SOCKET_POLL_INTERVAL: Duration = Duration::from_millis(5);

/// Maximum time a VM test is allowed to run before forced shutdown.
///
/// If the guest-side streams (vsock readers for test stdout/stderr and
/// init trace) do not close within this duration after the VM is
/// launched, [`TestVm::collect`] forcefully shuts down the hypervisor
/// and collects whatever output is available.  This prevents a hung
/// guest from blocking the test runner indefinitely while still
/// capturing the kernel console log, hypervisor output, and any partial
/// test output for diagnostics.
const VM_TEST_TIMEOUT: Duration = Duration::from_secs(60);

// ── Utilities ────────────────────────────────────────────────────────

/// Polls the filesystem until `path` exists, returning an error on timeout
/// or I/O failure.
///
/// Several sockets created by hypervisors and virtiofsd appear
/// asynchronously after a process is spawned.  This helper encapsulates
/// the retry loop.
///
/// The poll checks **file existence** only — it does not attempt a
/// connection.  This is the correct choice for **single-client**
/// servers such as virtiofsd's vhost-user socket, where a probe
/// `connect()` would be accepted as the real client connection and
/// break the server when the probe stream is immediately dropped.
///
/// For multi-client server sockets (e.g. QEMU QMP, cloud-hypervisor
/// REST API) where a probe connection is harmless, use
/// [`wait_for_socket_connectable`] instead.
pub(crate) async fn wait_for_socket(path: impl AsRef<Path>) -> Result<(), VmError> {
    let path = path.as_ref();
    for _ in 0..SOCKET_POLL_MAX_ATTEMPTS {
        match tokio::fs::try_exists(path).await {
            Ok(true) => return Ok(()),
            Ok(false) => {
                tokio::time::sleep(SOCKET_POLL_INTERVAL).await;
            }
            Err(err) => {
                return Err(VmError::SocketPoll {
                    path: path.to_path_buf(),
                    source: err,
                });
            }
        }
    }
    Err(VmError::SocketTimeout {
        path: path.to_path_buf(),
        timeout: SOCKET_POLL_INTERVAL.saturating_mul(SOCKET_POLL_MAX_ATTEMPTS),
    })
}

/// Like [`wait_for_socket`], but probes actual **connectivity** rather
/// than just file existence.
///
/// A Unix socket file appears on the filesystem after `bind()` but
/// before `listen()`.  If a caller immediately `connect()`s after the
/// file appears, it may hit `ECONNREFUSED` in that window.  This
/// variant retries through that gap by attempting a real connection on
/// each poll iteration.
///
/// **WARNING**: Do not use this for **single-client** servers (e.g.
/// virtiofsd's vhost-user socket).  The probe connection will be
/// accepted as the real client; when the probe stream is dropped the
/// server sees a client disconnect and may exit or stop accepting.
/// Use [`wait_for_socket`] (file-existence) for those.
#[allow(dead_code)]
pub(crate) async fn wait_for_socket_connectable(
    path: impl AsRef<Path>,
) -> Result<(), VmError> {
    let path = path.as_ref();
    for _ in 0..SOCKET_POLL_MAX_ATTEMPTS {
        match tokio::net::UnixStream::connect(path).await {
            Ok(_stream) => {
                // Connection succeeded — the server is listening.
                // We drop the stream immediately; we only needed to
                // confirm the socket is ready.
                return Ok(());
            }
            Err(err) => {
                use std::io::ErrorKind;
                match err.kind() {
                    // Socket file does not exist yet (pre-bind).
                    ErrorKind::NotFound |
                    // Socket file exists but nobody is listening yet
                    // (post-bind, pre-listen).
                    ErrorKind::ConnectionRefused => {
                        tokio::time::sleep(SOCKET_POLL_INTERVAL).await;
                    }
                    // Any other I/O error is unexpected — bail out.
                    _ => {
                        return Err(VmError::SocketPoll {
                            path: path.to_path_buf(),
                            source: err,
                        });
                    }
                }
            }
        }
    }
    Err(VmError::SocketTimeout {
        path: path.to_path_buf(),
        timeout: SOCKET_POLL_INTERVAL.saturating_mul(SOCKET_POLL_MAX_ATTEMPTS),
    })
}

/// Verifies that `/dev/kvm` is accessible inside the container.
///
/// Both cloud-hypervisor and QEMU require KVM for hardware-accelerated
/// virtualisation.  This pre-flight check runs before the hypervisor
/// process is spawned so that a missing or inaccessible `/dev/kvm`
/// produces a clear, early error rather than a cryptic child-process
/// failure.
///
/// # Errors
///
/// Returns [`VmError::KvmNotAccessible`] if `/dev/kvm` does not exist or
/// cannot be stat'd.
pub(crate) async fn check_kvm_accessible() -> Result<(), VmError> {
    match tokio::fs::try_exists("/dev/kvm").await {
        Ok(true) => Ok(()),
        Ok(false) => Err(VmError::KvmNotAccessible(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "/dev/kvm does not exist",
        ))),
        Err(err) => Err(VmError::KvmNotAccessible(err)),
    }
}

/// Verifies that `/dev/hugepages` is accessible inside the container.
///
/// Both cloud-hypervisor and QEMU require hugepage-backed memory for the
/// VM guest.  QEMU uses `-object memory-backend-file,mem-path=/dev/hugepages`
/// and cloud-hypervisor uses `MemoryConfig { hugepages: true, .. }`.
///
/// In scratch-mode containers `/dev/hugepages` must be present as a
/// hugetlbfs mount.  Privileged Docker containers normally inherit it
/// from the host, but if the host does not have hugetlbfs mounted there
/// (or the mount is not propagated), the hypervisor will crash
/// immediately after creating its control socket — producing a cryptic
/// "Connection reset by peer" (QEMU/QMP) or silent timeout
/// (cloud-hypervisor) rather than a clear error.
///
/// This pre-flight check runs before the hypervisor process is spawned
/// so that the missing mount produces a clear, actionable message.
///
/// When `host_page_size` is [`HostPageSize::Standard`], no hugepage
/// mount is needed and this check succeeds immediately.
///
/// # Errors
///
/// Returns [`VmError::HugepagesNotAccessible`] if `/dev/hugepages` does
/// not exist or cannot be stat'd and the host page size requires it.
pub(crate) async fn check_hugepages_accessible(
    host_page_size: config::HostPageSize,
) -> Result<(), VmError> {
    if !host_page_size.requires_hugepages() {
        return Ok(());
    }
    match tokio::fs::try_exists("/dev/hugepages").await {
        Ok(true) => Ok(()),
        Ok(false) => Err(VmError::HugepagesNotAccessible(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "/dev/hugepages does not exist; ensure hugetlbfs is mounted on the host \
             and propagated into the container",
        ))),
        Err(err) => Err(VmError::HugepagesNotAccessible(err)),
    }
}

/// Pre-flight diagnostics for the virtiofsd root share.
///
/// Logs detailed information about the vmroot filesystem state to help
/// diagnose guest init failures — especially `ENOEXEC` (error -8) which
/// indicates the kernel found the init binary but could not execute it.
///
/// Checks performed:
///
/// 1. The vmroot share directory ([`VM_ROOT_SHARE_PATH`]) exists.
/// 2. The `/nix/store` bind mount inside the vmroot is populated (not
///    the empty directory from the nix derivation).
/// 3. The init binary ([`INIT_BINARY_PATH`]) file metadata: size,
///    permissions, file type (regular vs symlink), and whether it is
///    executable.
/// 4. Full ELF header dump: magic, class (32/64), encoding (LE/BE),
///    `e_type` (EXEC/DYN/…), `e_machine`, `e_phnum`, and a hex dump
///    of the first 64 bytes so the developer can compare against
///    `readelf -h` on the host.
/// 5. Essential guest directories (`/dev`, `/proc`, `/sys`, `/tmp`,
///    `/run`) exist so the kernel can mount devtmpfs, procfs, etc.
///
/// This function never fails — it logs warnings and errors so the
/// developer can see what went wrong even when the VM subsequently
/// kernel-panics with an otherwise cryptic error code.
pub(crate) async fn diagnose_vmroot_share() {
    let root = VM_ROOT_SHARE_PATH;

    // ── 0. process identity ──────────────────────────────────────────
    //
    // virtiofsd inherits this UID/GID and opens files on the guest's
    // behalf using these credentials.  If the container user cannot
    // read files in the vmroot, virtiofsd will serve empty/error
    // responses and the kernel will see ENOEXEC.
    let uid = nix::unistd::getuid();
    let gid = nix::unistd::getgid();
    let euid = nix::unistd::geteuid();
    let egid = nix::unistd::getegid();
    info!(
        "vmroot diagnostics: process uid={uid} gid={gid} \
         euid={euid} egid={egid}"
    );

    // ── 1. vmroot share directory ────────────────────────────────────
    match tokio::fs::try_exists(root).await {
        Ok(true) => info!("vmroot share: {root} exists"),
        other => {
            error!("vmroot share: {root} not accessible: {other:?}");
            return;
        }
    }

    // ── 2. /nix/store bind mount ─────────────────────────────────────
    let nix_store = format!("{root}/nix/store");
    match tokio::fs::read_dir(&nix_store).await {
        Ok(mut entries) => {
            let has_entries = entries.next_entry().await.ok().flatten().is_some();
            if has_entries {
                info!("vmroot nix store: {nix_store} is populated (bind mount OK)");
            } else {
                error!(
                    "vmroot nix store: {nix_store} is EMPTY — the /nix/store \
                     bind mount into the vmroot share is not working.  \
                     Symlinks to /nix/store/* will not resolve in the VM guest, \
                     causing ENOEXEC (error -8) on the init binary."
                );
            }
        }
        Err(e) => error!("vmroot nix store: cannot read {nix_store}: {e}"),
    }

    // ── 3. init binary file metadata ─────────────────────────────────
    let init_path = format!("{root}{INIT_BINARY_PATH}");

    // Check symlink status first (lstat — does not follow symlinks).
    match tokio::fs::symlink_metadata(&init_path).await {
        Ok(meta) => {
            let ft = meta.file_type();
            if ft.is_symlink() {
                match tokio::fs::read_link(&init_path).await {
                    Ok(target) => warn!(
                        "vmroot init binary: {init_path} is a SYMLINK -> {target:?}. \
                         The guest kernel resolves symlinks via FUSE READLINK; \
                         if the target is an absolute /nix/store path it must \
                         be reachable through the virtiofs submount."
                    ),
                    Err(e) => warn!(
                        "vmroot init binary: {init_path} is a symlink but \
                         readlink failed: {e}"
                    ),
                }
            } else if ft.is_file() {
                info!("vmroot init binary: {init_path} is a regular file (not a symlink)");
            } else {
                error!(
                    "vmroot init binary: {init_path} is neither a regular file \
                     nor a symlink (file_type: {ft:?})"
                );
            }
        }
        Err(e) => {
            error!("vmroot init binary: cannot lstat {init_path}: {e}");
        }
    }

    // Stat the file (follows symlinks) for size and permissions.
    match tokio::fs::metadata(&init_path).await {
        Ok(meta) => {
            use std::os::unix::fs::PermissionsExt;
            let mode = meta.permissions().mode();
            let size = meta.len();
            let executable = mode & 0o111 != 0;
            info!(
                "vmroot init binary: {init_path} size={size} mode={mode:#06o} \
                 executable={executable}"
            );
            if !executable {
                error!(
                    "vmroot init binary: {init_path} is NOT executable \
                     (mode={mode:#06o}).  The kernel will fail with EACCES or \
                     ENOEXEC."
                );
            }
            if size == 0 {
                error!("vmroot init binary: {init_path} is EMPTY (0 bytes)");
            }
        }
        Err(e) => error!("vmroot init binary: cannot stat {init_path}: {e}"),
    }

    // ── 4. init binary ELF header ────────────────────────────────────
    //
    // Read the first 64 bytes (size of an ELF64 header) and parse the
    // key fields that the kernel's load_elf_binary() checks before
    // accepting the binary.
    match tokio::fs::File::open(&init_path).await {
        Ok(mut f) => {
            let mut hdr = [0u8; 64];
            match f.read_exact(&mut hdr).await {
                Ok(_) => {
                    diagnose_elf_header(&init_path, &hdr);
                }
                Err(e) => error!(
                    "vmroot init binary: failed to read 64-byte ELF header \
                     from {init_path}: {e}"
                ),
            }
        }
        Err(e) => error!("vmroot init binary: cannot open {init_path}: {e}"),
    }

    // ── 5. essential guest directories ───────────────────────────────
    for dir in ["/dev", "/proc", "/sys", "/tmp", "/run"] {
        let path = format!("{root}{dir}");
        match tokio::fs::try_exists(&path).await {
            Ok(true) => {}
            Ok(false) => warn!(
                "vmroot: {path} does not exist — the kernel cannot auto-mount \
                 {dir} (e.g. devtmpfs at /dev) on a read-only root filesystem.  \
                 Add 'mkdir -p $out{dir}' to the vmroot nix derivation."
            ),
            Err(e) => warn!("vmroot: cannot stat {path}: {e}"),
        }
    }

    // ── 6. canary binary readability ─────────────────────────────────
    //
    // The canary is a trivial ~200-byte non-PIE static ELF with no
    // CET notes and no nix store dependencies.  If the kernel also
    // gets ENOEXEC on this file, the issue is in the virtiofs data
    // path, not the binary format.
    let canary_path = format!("{root}/bin/canary-init");
    match tokio::fs::read(&canary_path).await {
        Ok(contents) => {
            let len = contents.len();
            let magic_ok = contents.len() >= 4 && contents[0..4] == *b"\x7fELF";
            let hex_head: String = contents
                .iter()
                .take(16)
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(" ");
            info!(
                "vmroot canary: {canary_path} readable from container \
                 (size={len}, ELF_magic={magic_ok}, head=[{hex_head}])"
            );
            if !magic_ok {
                error!(
                    "vmroot canary: {canary_path} does NOT have ELF magic. \
                     First 16 bytes: [{hex_head}]"
                );
            }
        }
        Err(e) => error!(
            "vmroot canary: CANNOT READ {canary_path} from container \
             as uid={uid}/euid={euid}: {e}  — if virtiofsd also cannot \
             read this file, the kernel will get empty data and ENOEXEC."
        ),
    }
}

/// Parses and logs the fields of a 64-byte ELF header buffer.
///
/// This is intentionally verbose so that the output can be compared
/// byte-for-byte against `readelf -h` on the host when diagnosing
/// ENOEXEC failures in the VM guest.
fn diagnose_elf_header(path: &str, hdr: &[u8; 64]) {
    // ── hex dump ─────────────────────────────────────────────────────
    let hex: String = hdr
        .chunks(16)
        .enumerate()
        .map(|(i, chunk)| {
            let hex_bytes: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
            format!("  {offset:04x}: {hex}", offset = i * 16, hex = hex_bytes.join(" "))
        })
        .collect::<Vec<_>>()
        .join("\n");
    info!("vmroot init binary: {path} first 64 bytes (ELF header):\n{hex}");

    // ── magic ────────────────────────────────────────────────────────
    if hdr[0..4] != *b"\x7fELF" {
        error!(
            "vmroot init binary: {path} does NOT have ELF magic \
             (first 4 bytes: {:02x?}).  If these look like ASCII path \
             characters (e.g. [2f 6e 69 78] = '/nix'), virtiofsd may be \
             returning the symlink target string instead of file contents.",
            &hdr[0..4]
        );
        return;
    }

    // ── e_ident fields ───────────────────────────────────────────────
    let ei_class = hdr[4];
    let ei_data = hdr[5];
    let ei_version = hdr[6];
    let ei_osabi = hdr[7];

    let class_str = match ei_class {
        1 => "ELF32",
        2 => "ELF64",
        _ => "UNKNOWN",
    };
    let data_str = match ei_data {
        1 => "little-endian (LSB)",
        2 => "big-endian (MSB)",
        _ => "UNKNOWN",
    };
    let osabi_str = match ei_osabi {
        0 => "ELFOSABI_NONE/SYSV",
        3 => "ELFOSABI_LINUX",
        _ => "other",
    };

    info!(
        "vmroot init binary: {path} e_ident: class={class_str}({ei_class}) \
         data={data_str}({ei_data}) version={ei_version} \
         osabi={osabi_str}({ei_osabi})"
    );

    if ei_class != 2 {
        error!(
            "vmroot init binary: {path} is NOT ELF64 (class={ei_class}). \
             The x86_64 kernel requires ELF64 binaries."
        );
        return;
    }
    if ei_data != 1 {
        error!(
            "vmroot init binary: {path} is NOT little-endian (data={ei_data}). \
             x86_64 requires LSB encoding."
        );
        return;
    }

    // ── ELF64 header fields (little-endian) ──────────────────────────
    let e_type = u16::from_le_bytes([hdr[16], hdr[17]]);
    let e_machine = u16::from_le_bytes([hdr[18], hdr[19]]);
    let e_version = u32::from_le_bytes([hdr[20], hdr[21], hdr[22], hdr[23]]);
    let e_entry = u64::from_le_bytes([
        hdr[24], hdr[25], hdr[26], hdr[27], hdr[28], hdr[29], hdr[30], hdr[31],
    ]);
    let e_phoff = u64::from_le_bytes([
        hdr[32], hdr[33], hdr[34], hdr[35], hdr[36], hdr[37], hdr[38], hdr[39],
    ]);
    let e_flags = u32::from_le_bytes([hdr[48], hdr[49], hdr[50], hdr[51]]);
    let e_ehsize = u16::from_le_bytes([hdr[52], hdr[53]]);
    let e_phentsize = u16::from_le_bytes([hdr[54], hdr[55]]);
    let e_phnum = u16::from_le_bytes([hdr[56], hdr[57]]);

    let type_str = match e_type {
        0 => "ET_NONE",
        1 => "ET_REL",
        2 => "ET_EXEC",
        3 => "ET_DYN (PIE or shared object)",
        4 => "ET_CORE",
        _ => "unknown",
    };
    let machine_str = match e_machine {
        0x3E => "EM_X86_64",
        0x03 => "EM_386",
        0xB7 => "EM_AARCH64",
        _ => "other",
    };

    info!(
        "vmroot init binary: {path} ELF64 header: \
         e_type={e_type}({type_str}) e_machine=0x{e_machine:x}({machine_str}) \
         e_version={e_version} e_entry=0x{e_entry:x} e_phoff={e_phoff} \
         e_flags=0x{e_flags:x} e_ehsize={e_ehsize} \
         e_phentsize={e_phentsize} e_phnum={e_phnum}"
    );

    // ── sanity checks ────────────────────────────────────────────────
    if e_machine != 0x3E {
        error!(
            "vmroot init binary: {path} e_machine=0x{e_machine:x} is NOT \
             EM_X86_64 (0x3e).  The kernel will return ENOEXEC."
        );
    }
    if e_type != 2 && e_type != 3 {
        error!(
            "vmroot init binary: {path} e_type={e_type} is neither ET_EXEC(2) \
             nor ET_DYN(3).  The kernel only executes these types."
        );
    }
    if e_type == 3 {
        info!(
            "vmroot init binary: {path} is ET_DYN (static-pie or dynamic). \
             If statically linked, the kernel handles this as a static PIE \
             executable (supported since Linux 5.x)."
        );
    }
    if e_phnum == 0 {
        error!(
            "vmroot init binary: {path} has NO program headers (e_phnum=0). \
             The kernel cannot load a binary with no segments."
        );
    }
    if e_ehsize != 64 {
        warn!(
            "vmroot init binary: {path} unexpected e_ehsize={e_ehsize} \
             (expected 64 for ELF64)"
        );
    }
}

// ── ProcessOutput ────────────────────────────────────────────────────

/// Collected stdout and stderr from a child process.
///
/// This replaces the previous `(bool, String, String)` tuple return from
/// `collect_process_output`, making call sites self-documenting and
/// enabling reuse as a sub-struct inside [`VmTestOutput`].
pub struct ProcessOutput {
    /// Whether the process exited successfully (status code 0).
    ///
    /// Set to `false` if the process exited with a non-zero status or if
    /// its output could not be collected due to an I/O error.
    pub success: bool,
    /// Captured stdout as a lossy UTF-8 string.
    pub stdout: String,
    /// Captured stderr as a lossy UTF-8 string.
    ///
    /// On I/O failure during collection, this contains a diagnostic
    /// message instead of the actual process output.
    pub stderr: String,
}

impl ProcessOutput {
    /// Waits for a child process to exit and collects its stdout/stderr as
    /// UTF-8 strings.
    ///
    /// On I/O failure the process is treated as failed and the error is
    /// placed in the stderr string so that it still appears in
    /// [`VmTestOutput`]'s `Display` output.
    async fn from_child(child: tokio::process::Child, label: &str) -> Self {
        match child.wait_with_output().await {
            Ok(output) => Self {
                success: output.status.success(),
                stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            },
            Err(err) => {
                error!("failed to collect {label} output: {err}");
                Self {
                    success: false,
                    stdout: String::new(),
                    stderr: format!("!!!OUTPUT UNAVAILABLE: {err}!!!"),
                }
            }
        }
    }

    /// Awaits a [`JoinHandle<String>`], returning a fallback message on
    /// panic or cancellation.
    ///
    /// This is an associated function rather than a constructor because it
    /// returns a raw `String` (for use as a single output channel like
    /// init-system tracing or kernel console output), not a full
    /// [`ProcessOutput`].  It lives here because it is always used
    /// alongside [`from_child`](Self::from_child) during the output
    /// collection phase of [`TestVm::collect`].
    async fn join_task_or_fallback(handle: JoinHandle<String>, label: &str) -> String {
        match handle.await {
            Ok(output) => output,
            Err(err) => {
                error!("failed to join {label} task: {err}");
                format!("!!!{} UNAVAILABLE: {err}!!!", label.to_uppercase())
            }
        }
    }

    /// Formats the stdout and stderr sections with the given label prefix
    /// for inclusion in [`VmTestOutput`]'s `Display` output.
    fn fmt_sections(&self, f: &mut std::fmt::Formatter<'_>, label: &str) -> std::fmt::Result {
        writeln!(f, "--------------- {label} stdout ---------------")?;
        writeln!(f, "{}", self.stdout)?;
        writeln!(f, "--------------- {label} stderr ---------------")?;
        writeln!(f, "{}", self.stderr)
    }
}

// ── TestVmParams ─────────────────────────────────────────────────────

/// Parameters that vary per test invocation and feed into the VM
/// configuration.
///
/// This struct carries the test identity (binary path, binary name, test
/// name) to the [`HypervisorBackend`], which is responsible for
/// translating these into its native configuration format (e.g. a
/// cloud-hypervisor [`VmConfig`], QEMU command-line arguments, etc.).
///
/// # Usage
///
/// ```ignore
/// let params = TestVmParams { full_bin_path, bin_name, test_name, vm_config, .. };
/// let vm = TestVm::<MyBackend>::launch(&params).await?;
/// ```
pub struct TestVmParams<'a> {
    /// Full path to the test binary (e.g. `/path/to/deps/my_test-abc123`).
    ///
    /// This is the host-side (container-side) path.  It is used as
    /// `argv[0]` when the container re-executes the test binary.
    pub full_bin_path: &'a Path,
    /// Path to the test binary as seen by the VM guest.
    ///
    /// The container mounts the binary directory at the well-known
    /// [`VM_TEST_BIN_DIR`](n_vm_protocol::VM_TEST_BIN_DIR) mount point
    /// inside `vmroot`, so the VM guest sees the binary at
    /// `/{VM_TEST_BIN_DIR}/{bin_name}`.  This path is passed on the
    /// kernel command line so that `n-it` can execute it.
    pub vm_bin_path: String,
    /// Short binary name (filename component only, e.g. `my_test-abc123`).
    pub bin_name: &'a str,
    /// Fully-qualified test name (e.g. `module::test_name`).
    pub test_name: &'a str,
    /// VM configuration controlling hypervisor memory backing, guest
    /// hugepage reservation, and virtual IOMMU.
    ///
    /// All fields have [`Default`] values matching the pre-refactor
    /// behaviour (1 GiB host hugepages, one 1 GiB guest hugepage, no
    /// vIOMMU).  The `#[in_vm]` proc macro constructs this from
    /// `#[hypervisor(…)]` and `#[guest(…)]` attributes.
    pub vm_config: config::VmConfig,
    /// Dynamically-allocated vsock resources for this VM instance.
    ///
    /// Vsock CIDs and `AF_VSOCK` port bindings are **host-global** (not
    /// namespaced by containers).  Each VM must use a unique allocation
    /// to avoid collisions when multiple tests run in parallel.
    ///
    /// See [`VsockAllocation`] for details on why this is necessary and
    /// how the ports are communicated to the guest init system.
    pub vsock: VsockAllocation,
}

// ── VmTestOutput ─────────────────────────────────────────────────────

/// Collected output from a test that ran inside a VM.
///
/// This struct aggregates all observable output from the three-tier test
/// execution (hypervisor events, kernel console, init system tracing, and the
/// test's own stdout/stderr).  Its [`Display`](std::fmt::Display) implementation
/// formats everything into labelled sections for easy reading in test failure
/// output.
///
/// The generic parameter `B` selects the hypervisor backend, which
/// determines the concrete type of the event log.
///
/// Test stdout and stderr are collected via dedicated
/// [`VsockChannel`]s, so they are cleanly separated from each other and
/// from the hypervisor process's own diagnostic output.
pub struct VmTestOutput<B: HypervisorBackend> {
    /// Whether the test passed and all infrastructure exited successfully.
    ///
    /// This is `true` only when **all** of the following hold:
    ///
    /// 1. The Rust test harness did not report failure in its stdout
    ///    summary line (`test result: FAILED`).
    /// 2. The hypervisor reported a clean VM shutdown (no guest panic, no
    ///    event-stream errors).
    /// 3. The hypervisor process exited with status 0.
    /// 4. The virtiofsd process exited with status 0.
    pub success: bool,
    /// Captured stdout and stderr from the test process (via vsock).
    pub test: ProcessOutput,
    /// Kernel serial console output (from the guest's `ttyS0`).
    pub console: String,
    /// Tracing output from the `n-it` init system, streamed via vsock.
    pub init_trace: String,
    /// Captured stdout, stderr, and exit status of the hypervisor process
    /// itself.
    pub hypervisor: ProcessOutput,
    /// Hypervisor lifecycle events collected during the VM's lifetime.
    ///
    /// The concrete type is determined by the backend (e.g.
    /// cloud-hypervisor's event monitor JSON stream, QEMU's QMP events).
    pub hypervisor_events: B::EventLog,
    /// Captured stdout, stderr, and exit status of the virtiofsd process.
    pub virtiofsd: ProcessOutput,
}

impl<B: HypervisorBackend> std::fmt::Display for VmTestOutput<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "=============== in_vm TEST RESULTS ===============")?;
        writeln!(f, "--------------- {} events ---------------", B::NAME)?;
        write!(f, "{}", self.hypervisor_events)?;
        self.hypervisor.fmt_sections(f, B::NAME)?;
        self.virtiofsd.fmt_sections(f, "virtiofsd")?;
        writeln!(f, "--------------- linux console ---------------")?;
        writeln!(f, "{}", self.console)?;
        writeln!(f, "--------------- init system ---------------")?;
        writeln!(f, "{}", self.init_trace)?;
        self.test.fmt_sections(f, "test")?;
        Ok(())
    }
}

// ── TestVm ───────────────────────────────────────────────────────────

/// Owns all long-lived resources for a running test VM.
///
/// The generic parameter `B` selects the hypervisor backend
/// (cloud-hypervisor, QEMU, etc.), which determines the concrete types
/// for lifecycle control and event monitoring.
///
/// The two-phase API ([`launch`](Self::launch) -> [`collect`](Self::collect))
/// separates concerns:
///
/// - **`launch`** handles environment preparation, process spawning, and VM
///   boot.  If any step fails it returns a [`VmError`] and all resources
///   created so far are cleaned up via `Drop` (child processes use
///   `kill_on_drop(true)`; spawned tasks are cancelled when the tokio
///   runtime shuts down).
///
/// - **`collect`** waits for the test to complete, gathers output from every
///   subsystem, performs a best-effort shutdown, and assembles a
///   [`VmTestOutput`].  It always succeeds -- individual subsystem failures
///   are recorded as degraded output rather than hard errors, because the
///   primary goal is to give the developer as much diagnostic information
///   as possible.
pub struct TestVm<B: HypervisorBackend> {
    /// The hypervisor child process.
    hypervisor: tokio::process::Child,
    /// The virtiofsd child process.
    virtiofsd: tokio::process::Child,
    /// Backend-specific handle for lifecycle control (e.g. REST API
    /// client for cloud-hypervisor, QMP connection for QEMU).
    controller: B::Controller,
    /// Background task watching hypervisor lifecycle events.
    ///
    /// Wrapped in [`AbortOnDrop`] so the task is automatically aborted if
    /// the `TestVm` is dropped without calling [`collect`](Self::collect)
    /// (e.g. due to a panic in surrounding code).
    event_watcher: AbortOnDrop<(B::EventLog, HypervisorVerdict)>,
    /// Background task collecting init system tracing output via vsock.
    init_trace: AbortOnDrop<String>,
    /// Background task collecting test process stdout via vsock.
    test_stdout: AbortOnDrop<String>,
    /// Background task collecting test process stderr via vsock.
    test_stderr: AbortOnDrop<String>,
    /// Background task collecting kernel serial console output.
    kernel_log: AbortOnDrop<String>,
}

impl<B: HypervisorBackend> TestVm<B> {
    /// Spawns a virtiofsd process that shares `path` into the VM as a
    /// read-only virtiofs mount.
    async fn launch_virtiofsd(path: impl AsRef<Path>) -> Result<tokio::process::Child, VmError> {
        let uid = nix::unistd::getuid().as_raw();
        let gid = nix::unistd::getgid().as_raw();
        tokio::process::Command::new(VIRTIOFSD_BINARY_PATH)
            .arg("--shared-dir")
            .arg(path.as_ref())
            .arg("--readonly")
            .arg("--tag")
            .arg(VIRTIOFS_ROOT_TAG)
            .arg("--socket-path")
            .arg(VIRTIOFSD_SOCKET_PATH)
            .arg("--announce-submounts")
            .arg("--sandbox=none")
            .arg("--rlimit-nofile=0")
            .arg(format!(
                "--translate-uid=squash-host:0:{uid}:{MAX}",
                MAX = u32::MAX
            ))
            .arg(format!(
                "--translate-gid=squash-host:0:{gid}:{MAX}",
                MAX = u32::MAX
            ))
            .stdin(Stdio::null())
            .stderr(Stdio::piped())
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(VmError::VirtiofsdSpawn)
    }

    /// Spawns a background task that connects to the kernel serial console
    /// socket and reads it to EOF.
    ///
    /// The console socket is created by the hypervisor after the VM boots,
    /// so the task polls for its existence before attempting to connect.
    fn spawn_kernel_log_reader() -> AbortOnDrop<String> {
        AbortOnDrop::spawn(async move {
            if let Err(e) = wait_for_socket(KERNEL_CONSOLE_SOCKET_PATH).await {
                return format!("!!!KERNEL LOG UNAVAILABLE: socket not ready: {e}!!!");
            }
            match tokio::net::UnixStream::connect(KERNEL_CONSOLE_SOCKET_PATH).await {
                Ok(mut stream) => {
                    let mut log = String::with_capacity(16_384);
                    if let Err(e) = stream.read_to_string(&mut log).await {
                        warn!("error reading kernel console: {e}");
                    }
                    log
                }
                Err(e) => format!("!!!KERNEL LOG UNAVAILABLE: connect failed: {e}!!!"),
            }
        })
    }

    /// Prepares the environment and boots the VM.
    ///
    /// This method orchestrates four phases:
    ///
    /// 1. [`launch_virtiofsd`](Self::launch_virtiofsd) -- share the
    ///    container filesystem into the VM.
    /// 2. [`B::spawn_vsock_reader`](HypervisorBackend::spawn_vsock_reader)
    ///    -- bind backend-specific vsock listeners for all channels.
    /// 3. [`B::launch`](HypervisorBackend::launch) -- delegate to the
    ///    backend for hypervisor-specific process spawning, VM
    ///    configuration, boot, and event monitoring.
    /// 4. [`spawn_kernel_log_reader`](Self::spawn_kernel_log_reader) --
    ///    start collecting kernel console output.
    ///
    /// All background tasks are wrapped in [`AbortOnDrop`], so if any phase
    /// fails (or the method panics), previously spawned tasks are
    /// automatically aborted when their handles drop.  Child processes use
    /// `kill_on_drop(true)` for the same guarantee.
    pub async fn launch(params: &TestVmParams<'_>) -> Result<Self, VmError> {
        // Validate memory alignment before any process spawning so that
        // misconfigurations (e.g. 1 GiB host page size with a non-GiB-
        // aligned VM memory size) produce a clear message rather than an
        // opaque hypervisor crash.
        params
            .vm_config
            .validate_memory_alignment()
            .unwrap_or_else(|msg| panic!("VM configuration error: {msg}"));

        // Run pre-flight diagnostics on the vmroot filesystem before
        // starting virtiofsd.  This catches common misconfigurations
        // (empty /nix/store bind mount, missing /dev directory, broken
        // symlinks) and logs actionable error messages instead of letting
        // the VM kernel-panic with a cryptic ENOEXEC.
        diagnose_vmroot_share().await;

        let mut virtiofsd = Self::launch_virtiofsd(VM_ROOT_SHARE_PATH).await?;

        // virtiofsd creates its Unix socket asynchronously after the
        // process starts.  Both hypervisor backends reference this socket
        // at launch time -- QEMU connects to it via `-chardev socket,…`
        // during process startup, and cloud-hypervisor connects during
        // `boot_vm()` when it initialises the vhost-user-fs device.  If
        // we proceed before the socket exists, the hypervisor fails with
        // an opaque error (QEMU: SocketTimeout on the QMP socket because
        // QEMU exits immediately; cloud-hypervisor: "Cannot create
        // virtio-fs device" / "Connection to socket failed").
        if let Err(err) = wait_for_socket(VIRTIOFSD_SOCKET_PATH).await {
            // virtiofsd most likely exited before creating its socket.
            // Capture its stderr to surface the actual failure reason
            // (e.g. a missing capability, AppArmor denial, or permission
            // error) instead of just reporting a socket timeout.
            config::drain_child_stderr(&mut virtiofsd, "virtiofsd").await;
            return Err(err);
        }

        // All listeners must be bound *before* the VM boots so that the
        // guest-side vsock connections succeed immediately.  The listener
        // type is backend-specific: cloud-hypervisor uses Unix sockets,
        // QEMU uses AF_VSOCK via the kernel's vhost-vsock module.
        let init_trace = B::spawn_vsock_reader(&params.vsock.init_trace)?;
        let test_stdout = B::spawn_vsock_reader(&params.vsock.test_stdout)?;
        let test_stderr = B::spawn_vsock_reader(&params.vsock.test_stderr)?;

        let launched = B::launch(params).await?;

        let kernel_log = Self::spawn_kernel_log_reader();

        Ok(Self {
            hypervisor: launched.child,
            virtiofsd,
            controller: launched.controller,
            event_watcher: launched.event_watcher,
            init_trace,
            test_stdout,
            test_stderr,
            kernel_log,
        })
    }

    /// Waits for the test to finish and collects output from all subsystems.
    ///
    /// This method consumes the `TestVm`, shutting down the hypervisor and
    /// virtiofsd after collecting their output.  Individual subsystem
    /// failures are recorded as degraded output (e.g.
    /// `"!!!...UNAVAILABLE...!!!"`) rather than propagated as errors, because
    /// the primary goal is to give the developer as much diagnostic
    /// information as possible even when things go wrong.
    pub async fn collect(self) -> VmTestOutput<B> {
        let Self {
            hypervisor,
            virtiofsd,
            controller,
            event_watcher,
            init_trace,
            test_stdout,
            test_stderr,
            kernel_log,
        } = self;

        // Extract the inner JoinHandles from AbortOnDrop wrappers.
        // This disarms the abort-on-drop behavior -- from this point on,
        // we own the handles directly and will await them below.
        let event_watcher = event_watcher.into_inner();
        let init_trace = init_trace.into_inner();
        let test_stdout = test_stdout.into_inner();
        let test_stderr = test_stderr.into_inner();
        let kernel_log = kernel_log.into_inner();

        // ── Phase 1: wait for the VM to reach a terminal state ───
        //
        // The event watcher completes when the hypervisor emits a
        // terminal event (Shutdown / Panic) or the event pipe closes.
        // If the guest hangs, the timeout fires instead.  In either
        // case we call B::shutdown() afterward -- it is idempotent,
        // so in the happy path it harmlessly confirms the VM is
        // already down, while in the timeout path it force-kills the
        // guest and unblocks all pending stream readers.
        let (hypervisor_events, hypervisor_verdict) = tokio::select! {
            biased;
            result = event_watcher => {
                match result {
                    Ok(r) => r,
                    Err(err) => {
                        error!("hypervisor event watcher task failed: {err}");
                        (B::EventLog::default(), HypervisorVerdict::Failure)
                    }
                }
            }
            _ = tokio::time::sleep(VM_TEST_TIMEOUT) => {
                warn!(
                    "VM test did not complete within {VM_TEST_TIMEOUT:?}; \
                     forcing hypervisor shutdown to collect diagnostics"
                );
                (B::EventLog::default(), HypervisorVerdict::Failure)
            }
        };

        B::shutdown(&controller).await;

        // ── Phase 2: collect output from all subsystems ──────────
        //
        // After shutdown the hypervisor process exits, which closes
        // the vsock streams and serial console socket.  All pending
        // readers should complete promptly.  A safety-net timeout on
        // each prevents a misbehaving reader from blocking forever.
        const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

        let init_trace =
            drain_or_fallback(init_trace, "init system trace", DRAIN_TIMEOUT).await;
        let test_stdout =
            drain_or_fallback(test_stdout, "test stdout", DRAIN_TIMEOUT).await;
        let test_stderr =
            drain_or_fallback(test_stderr, "test stderr", DRAIN_TIMEOUT).await;

        let hypervisor_output = ProcessOutput::from_child(hypervisor, B::NAME).await;

        let kernel_log =
            drain_or_fallback(kernel_log, "kernel log", DRAIN_TIMEOUT).await;

        let virtiofsd_output = ProcessOutput::from_child(virtiofsd, "virtiofsd").await;

        // The Rust test harness (invoked with `--format=terse`) writes a
        // summary line to stdout:
        //
        //   test result: ok. 1 passed; 0 failed; ...
        //   test result: FAILED. 0 passed; 1 failed; ...
        //
        // We check for the failure marker so that a test-level failure is
        // not masked by a clean infrastructure shutdown.  This is the most
        // reliable signal available without modifying the init system to
        // forward the test process's exit code over a dedicated channel.
        let test_passed = !test_stdout.contains("test result: FAILED");

        let test_output = ProcessOutput {
            // The test process runs inside the VM -- its exit code is not
            // directly observable from the container tier.  We rely on the
            // test harness summary line (checked via test_passed above) and
            // on n-it's behavior of aborting on test failure (which triggers
            // a guest panic detected by hypervisor_verdict).
            success: test_passed,
            stdout: test_stdout,
            stderr: test_stderr,
        };

        VmTestOutput {
            success: test_output.success
                && virtiofsd_output.success
                && hypervisor_verdict.is_success()
                && hypervisor_output.success,
            test: test_output,
            console: kernel_log,
            init_trace,
            hypervisor: hypervisor_output,
            hypervisor_events,
            virtiofsd: virtiofsd_output,
        }
    }
}

/// Awaits a [`JoinHandle<String>`] with a timeout, returning a fallback
/// diagnostic message if the task does not complete in time.
///
/// Used during [`TestVm::collect`]'s drain phase to prevent a
/// misbehaving stream reader from blocking output collection after the
/// hypervisor has been shut down.
async fn drain_or_fallback(
    handle: JoinHandle<String>,
    label: &str,
    timeout: Duration,
) -> String {
    match tokio::time::timeout(
        timeout,
        ProcessOutput::join_task_or_fallback(handle, label),
    )
    .await
    {
        Ok(output) => output,
        Err(_) => {
            warn!("{label} did not complete within {timeout:?} after shutdown");
            format!(
                "!!!{} UNAVAILABLE: timed out after shutdown!!!",
                label.to_uppercase()
            )
        }
    }
}

// ── run_in_vm ────────────────────────────────────────────────────────

/// Boots a VM using the given [`HypervisorBackend`] and runs the test
/// function inside it.
///
/// Allocates a random set of vsock resources (CID + three channel ports).
///
/// The CID is chosen uniformly from the valid guest range
/// ([`VsockCid::GUEST_MIN`]..=[`VsockCid::GUEST_MAX`]) and the three
/// ports are chosen uniformly from the dynamic range
/// ([`VsockPort::DYNAMIC_MIN`]..=[`VsockPort::DYNAMIC_MAX`]) with a gap
/// of 3 between the base and the last port.
///
/// With ~4 billion possible CIDs and ~4 billion possible port bases, the
/// probability of collision between two concurrent tests is negligible
/// (~1 in 4 × 10⁹).
fn allocate_vsock_resources() -> VsockAllocation {
    let mut rng = rand::rng();

    let cid = rng.random_range(VsockCid::GUEST_MIN.as_raw()..=VsockCid::GUEST_MAX.as_raw());

    // Pick a port base and reserve 3 consecutive ports (trace, stdout,
    // stderr).  Ensure the base + 2 does not overflow past DYNAMIC_MAX.
    let port_max = VsockPort::DYNAMIC_MAX.as_raw() - 2;
    let port_base = rng.random_range(VsockPort::DYNAMIC_MIN.as_raw()..=port_max);

    VsockAllocation {
        cid: VsockCid::new(cid),
        init_trace: VsockChannel {
            port: VsockPort::new(port_base),
            label: "init-trace",
        },
        test_stdout: VsockChannel {
            port: VsockPort::new(port_base + 1),
            label: "test-stdout",
        },
        test_stderr: VsockChannel {
            port: VsockPort::new(port_base + 2),
            label: "test-stderr",
        },
    }
}

/// Convenience wrapper that launches a VM, runs the test, and collects
/// output.
///
/// This is the **container-tier** entry point, called from the code
/// generated by `#[in_vm]` when `IN_TEST_CONTAINER=YES`.  It:
///
/// 1. Allocates unique vsock resources (CID + ports) via
///    [`allocate_vsock_resources`] so that parallel test runs do not
///    collide on the host-global `AF_VSOCK` address space.
/// 2. Resolves the test identity from the type parameter and `argv[0]`.
/// 3. Delegates to [`TestVm::launch`] to prepare and boot the VM.
/// 4. Delegates to [`TestVm::collect`] to wait for the test and gather
///    output.
///
/// The type parameter `B` selects the hypervisor backend.  The `#[in_vm]`
/// proc macro currently passes
/// [`CloudHypervisor`](crate::cloud_hypervisor::CloudHypervisor), but
/// callers can substitute any backend that implements
/// [`HypervisorBackend`].
///
/// The type parameter `F` is used only to derive the test name via
/// [`std::any::type_name`]; the function itself is never called in this
/// tier.
///
/// # Errors
///
/// Returns [`VmError`] if any part of the VM launch sequence fails.
/// Output collection is best-effort and never fails -- see
/// [`TestVm::collect`].
pub async fn run_in_vm<B: HypervisorBackend, F: FnOnce()>(
    _: F,
    vm_config: config::VmConfig,
) -> Result<VmTestOutput<B>, VmError> {
    let identity = crate::test_identity::TestIdentity::resolve::<F>();
    let test_name = identity.test_name;

    let full_bin_path = std::env::args().next().ok_or(VmError::MissingArgv)?;
    let (_, bin_name) =
        full_bin_path
            .rsplit_once("/")
            .ok_or_else(|| VmError::InvalidBinaryPath {
                path: PathBuf::from(&full_bin_path),
            })?;

    let vm_bin_path = format!("/{}/{bin_name}", n_vm_protocol::VM_TEST_BIN_DIR);

    let vsock = allocate_vsock_resources();
    info!("allocated vsock resources: {vsock}");

    let params = TestVmParams {
        full_bin_path: Path::new(&full_bin_path),
        vm_bin_path,
        bin_name,
        test_name,
        vm_config,
        vsock,
    };

    let vm = TestVm::<B>::launch(&params).await?;
    Ok(vm.collect().await)
}
