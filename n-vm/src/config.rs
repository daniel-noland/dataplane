// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Shared VM configuration constants and helpers used by all hypervisor
//! backends.
//!
//! Both the cloud-hypervisor and QEMU backends run the same test
//! environment with matching VM specifications.  This module provides a
//! single source of truth for values that were previously duplicated
//! across `cloud_hypervisor/mod.rs` and `qemu/mod.rs`.
//!
//! # Organisation
//!
//! - **VM sizing** -- memory, hugepage, and vCPU constants.
//! - **CPU topology** -- socket / die / core / thread layout.
//! - **NIC model** -- the emulated network card type presented to the
//!   guest ([`NicModel`]).
//! - **Network interfaces** -- identifiers, tap device names, MAC
//!   addresses.
//! - **Device tuning** -- virtio queue depths, buffer capacities.
//! - **Timeouts** -- post-panic event drain duration.
//! - **Kernel command line** -- the parameterised command line passed to
//!   the guest kernel (previously duplicated verbatim in both backends).
//! - **Utility functions** -- shared async helpers for vsock stream
//!   reading and child-process stderr capture.

use std::time::Duration;

use n_vm_protocol::{INIT_BINARY_PATH, VsockAllocation};
use tokio::io::AsyncReadExt;
use tracing::{error, warn};

// ── NIC model ────────────────────────────────────────────────────────

/// Network interface card model presented to the VM guest.
///
/// This controls the emulated (or paravirtualised) NIC type for **all**
/// network interfaces in the VM.  The choice affects both the QEMU
/// device string and the guest driver that claims the device:
///
/// - [`VirtioNet`](Self::VirtioNet) -- paravirtualised `virtio-net-pci`.
///   Supported by **both** cloud-hypervisor and QEMU.  This is the
///   default and should be used unless the test specifically needs a
///   legacy NIC model.
///
/// - [`E1000`](Self::E1000) -- Intel 82540EM Gigabit Ethernet
///   (`e1000` device).  Supported by **QEMU only**.  Cloud-hypervisor
///   does not implement hardware-emulated NIC models, so using this
///   variant with the cloud-hypervisor backend is a compile-time error
///   (enforced by the `#[in_vm]` proc macro).
///
/// # Backend compatibility
///
/// | Model | cloud-hypervisor | QEMU |
/// |-------|-----------------|------|
/// | `VirtioNet` | ✅ | ✅ |
/// | `E1000` | ❌ | ✅ |
///
/// The `#[network(nic_model = "e1000")]` attribute is only accepted
/// when used with `#[in_vm(qemu)]`.  The proc macro emits a
/// compile-time error for incompatible combinations.
///
/// # IOMMU interaction
///
/// When the virtual IOMMU is enabled (`#[hypervisor(iommu)]`):
///
/// - **VirtioNet** devices use `iommu_platform=on,ats=on` (QEMU) or
///   per-device IOMMU flags (cloud-hypervisor) for full DMA remapping
///   with address translation services.
/// - **E1000** devices sit behind the Intel IOMMU on QEMU's PCI bus
///   (DMA is remapped) but do not support `iommu_platform` or ATS
///   because the e1000 is not a virtio device.  DPDK's VFIO driver
///   will use the IOMMU for these devices automatically.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum NicModel {
    /// Paravirtualised virtio-net (default).
    ///
    /// Uses `virtio-net-pci-non-transitional` on QEMU and the native
    /// virtio-net implementation on cloud-hypervisor.
    #[default]
    VirtioNet,

    /// Intel 82540EM Gigabit Ethernet (QEMU `e1000` device).
    ///
    /// This is a fully emulated legacy NIC.  It is significantly slower
    /// than virtio-net but useful for testing guest drivers that must
    /// interact with hardware-like register interfaces.
    ///
    /// **QEMU only** -- cloud-hypervisor does not support emulated NIC
    /// models.
    E1000,
}

impl NicModel {
    /// Returns `true` if this NIC model is virtio-based.
    ///
    /// Virtio NICs support `iommu_platform` and `ats` flags when the
    /// virtual IOMMU is enabled; non-virtio models do not.
    #[must_use]
    pub const fn is_virtio(self) -> bool {
        matches!(self, Self::VirtioNet)
    }

    /// Returns `true` if this NIC model requires QEMU.
    ///
    /// Cloud-hypervisor only supports virtio devices; emulated hardware
    /// models like e1000 are QEMU-specific.
    #[must_use]
    pub const fn requires_qemu(self) -> bool {
        matches!(self, Self::E1000)
    }
}

// ── Page-size configuration ──────────────────────────────────────────

/// Page size used by the hypervisor to back VM memory on the host.
///
/// This controls how the hypervisor allocates memory for the guest:
///
/// - [`Standard`](Self::Standard) -- plain 4 KiB pages via
///   `MAP_SHARED` (cloud-hypervisor) or `memory-backend-memfd` (QEMU).
///   No hugetlbfs mount is required on the host.
/// - [`Huge2M`](Self::Huge2M) / [`Huge1G`](Self::Huge1G) -- hugepage-
///   backed memory via `MAP_HUGETLB` (cloud-hypervisor) or
///   `memory-backend-file,mem-path=/dev/hugepages` (QEMU).  Requires a
///   hugetlbfs mount with the matching page size.
///
/// The host page size is independent of the guest-side hugepage
/// reservation ([`GuestHugePageConfig`]): you can back a VM with 4 KiB
/// host pages while the guest kernel reserves 2 MiB hugepages for DPDK,
/// or vice versa.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum HostPageSize {
    /// Standard 4 KiB pages.  No hugepage mount required on the host.
    Standard,
    /// 2 MiB huge pages.
    Huge2M,
    /// 1 GiB huge pages.
    #[default]
    Huge1G,
}

impl HostPageSize {
    /// Size in bytes of a single page at this page size.
    #[must_use]
    pub const fn bytes(self) -> i64 {
        match self {
            Self::Standard => 4 * 1024,
            Self::Huge2M => 2 * 1024 * 1024,
            Self::Huge1G => 1024 * 1024 * 1024,
        }
    }

    /// Whether this page size requires a hugetlbfs mount on the host.
    #[must_use]
    pub const fn requires_hugepages(self) -> bool {
        match self {
            Self::Standard => false,
            Self::Huge2M | Self::Huge1G => true,
        }
    }
}

/// Hugepage size for guest kernel command-line reservation.
///
/// Used by [`GuestHugePageConfig::Allocate`] to specify the page
/// granularity of the guest-side hugepage pool (the `hugepagesz=`
/// and `default_hugepagesz=` kernel parameters).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestHugePageSize {
    /// 2 MiB guest hugepages.
    Huge2M,
    /// 1 GiB guest hugepages.
    Huge1G,
}

impl GuestHugePageSize {
    /// The kernel command-line size suffix (e.g. `"2M"`, `"1G"`).
    #[must_use]
    pub const fn kernel_suffix(self) -> &'static str {
        match self {
            Self::Huge2M => "2M",
            Self::Huge1G => "1G",
        }
    }

    /// Size in bytes of a single hugepage at this granularity.
    #[must_use]
    pub const fn bytes(self) -> i64 {
        match self {
            Self::Huge2M => 2 * 1024 * 1024,
            Self::Huge1G => 1024 * 1024 * 1024,
        }
    }
}

/// Guest hugepage reservation passed on the kernel command line.
///
/// Controls the `default_hugepagesz`, `hugepagesz`, and `hugepages`
/// kernel parameters that reserve a pool of hugepages at boot time
/// for DPDK to use.
///
/// The guest hugepage configuration is independent of the host-side
/// page size ([`HostPageSize`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestHugePageConfig {
    /// No guest hugepages.  DPDK must use `--no-huge`.
    None,
    /// Reserve hugepages of the given size and count.
    Allocate {
        /// Hugepage granularity.
        size: GuestHugePageSize,
        /// Number of hugepages to reserve.
        count: u32,
    },
}

impl Default for GuestHugePageConfig {
    /// Returns 1 × 1 GiB hugepage — matching the pre-refactor default.
    ///
    /// Cannot use `#[derive(Default)]` because the default variant
    /// carries fields.
    fn default() -> Self {
        Self::Allocate {
            size: GuestHugePageSize::Huge1G,
            count: 1,
        }
    }
}

impl GuestHugePageConfig {
    /// Builds the kernel command-line fragment for hugepage reservation.
    ///
    /// Returns an empty string when no hugepages are requested
    /// ([`None`](Self::None)), or the `default_hugepagesz=…
    /// hugepagesz=… hugepages=…` triplet with a trailing space when
    /// they are.
    pub(crate) fn kernel_cmdline_fragment(&self) -> String {
        match self {
            Self::None => String::new(),
            Self::Allocate { size, count } => {
                let sz = size.kernel_suffix();
                format!("default_hugepagesz={sz} hugepagesz={sz} hugepages={count} ")
            }
        }
    }
}

/// Complete VM configuration passed through the dispatch chain.
///
/// Constructed by the `#[in_vm]` proc macro from `#[in_vm(…)]`,
/// `#[hypervisor(…)]`, `#[guest(…)]`, and `#[network(…)]` attributes,
/// then carried through [`run_container_tier`] →
/// [`run_in_vm`] →
/// [`TestVmParams`].
///
/// All fields have [`Default`] values matching the pre-refactor
/// behaviour: 1 GiB host hugepages, one 1 GiB guest hugepage,
/// no vIOMMU, virtio-net NICs.
///
/// [`run_container_tier`]: crate::dispatch::run_container_tier
/// [`run_in_vm`]: crate::vm::run_in_vm
/// [`TestVmParams`]: crate::vm::TestVmParams
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VmConfig {
    /// Whether to present a virtual IOMMU device to the guest.
    pub iommu: bool,
    /// Page size backing the VM's memory on the host.
    pub host_page_size: HostPageSize,
    /// Guest hugepage reservation for the kernel command line.
    pub guest_hugepages: GuestHugePageConfig,
    /// NIC model for all network interfaces in the VM.
    ///
    /// Defaults to [`VirtioNet`](NicModel::VirtioNet).  The
    /// [`E1000`](NicModel::E1000) variant is only valid with the QEMU
    /// backend; the `#[in_vm]` proc macro enforces this at compile
    /// time.
    pub nic_model: NicModel,
}

impl VmConfig {
    /// Checks that the VM memory is properly aligned for the host page
    /// size and that guest hugepage reservations fit within VM memory.
    ///
    /// Called during [`TestVm::launch`] before spawning the hypervisor
    /// process so that misconfigurations produce clear errors rather
    /// than opaque hypervisor crashes.
    ///
    /// # Errors
    ///
    /// Returns a human-readable error string if validation fails.
    ///
    /// [`TestVm::launch`]: crate::vm::TestVm::launch
    pub fn validate_memory_alignment(&self) -> Result<(), String> {
        let page_bytes = self.host_page_size.bytes();
        if VM_MEMORY_BYTES % page_bytes != 0 {
            return Err(format!(
                "VM_MEMORY_BYTES ({VM_MEMORY_BYTES}) is not aligned to \
                 host page size ({page_bytes} bytes)",
            ));
        }
        if let GuestHugePageConfig::Allocate { size, count } = self.guest_hugepages {
            let required = size.bytes() * i64::from(count);
            if required > VM_MEMORY_BYTES {
                return Err(format!(
                    "guest hugepage reservation ({count} × {} = {required} bytes) \
                     exceeds VM memory ({VM_MEMORY_BYTES} bytes)",
                    size.bytes(),
                ));
            }
        }
        Ok(())
    }
}

// ── VM sizing ────────────────────────────────────────────────────────

/// Total guest memory in MiB (1 GiB).
///
/// Must be a multiple of the configured [`HostPageSize`].
/// Use [`VmConfig::validate_memory_alignment`] to verify this at
/// launch time.
pub(crate) const VM_MEMORY_MIB: u32 = 1024;

/// Total guest memory in bytes (1 GiB).
///
/// Derived from [`VM_MEMORY_MIB`].  Used by the cloud-hypervisor backend
/// whose API accepts byte counts.
pub(crate) const VM_MEMORY_BYTES: i64 = (VM_MEMORY_MIB as i64) * 1024 * 1024;

// ── CPU topology ─────────────────────────────────────────────────────
//
// The topology must satisfy:
//   VM_SOCKETS × VM_DIES_PER_PACKAGE × VM_CORES_PER_DIE × VM_THREADS_PER_CORE == VM_VCPUS
//
// Both hypervisor backends translate these into their native topology
// format (cloud-hypervisor `CpuTopology`, QEMU `-smp` arguments).

/// Number of vCPUs.
pub(crate) const VM_VCPUS: u32 = 6;

/// Threads per core in the CPU topology.
pub(crate) const VM_THREADS_PER_CORE: u32 = 2;

/// Cores per die in the CPU topology.
pub(crate) const VM_CORES_PER_DIE: u32 = 1;

/// Dies per package (socket) in the CPU topology.
pub(crate) const VM_DIES_PER_PACKAGE: u32 = 3;

/// Number of sockets in the CPU topology.
pub(crate) const VM_SOCKETS: u32 = 1;

// ── Network interfaces ───────────────────────────────────────────────

/// Describes a network interface shared across all hypervisor backends.
///
/// Each backend translates these descriptors into its native format:
/// cloud-hypervisor builds [`NetConfig`] structs with additional MTU and
/// queue-size fields; QEMU builds `-netdev` / `-device` argument pairs.
///
/// The MAC addresses and tap device names must match between backends so
/// that the VM guest sees an identical network environment regardless of
/// the hypervisor used.
pub(crate) struct NetIface {
    /// Unique identifier used in device configuration (e.g. `"mgmt"`,
    /// `"fabric1"`).
    pub id: &'static str,
    /// TAP device name on the host.
    pub tap: &'static str,
    /// MAC address in `XX:XX:XX:XX:XX:XX` format.
    pub mac: &'static str,
}

/// The management network interface (standard Ethernet).
pub(crate) const IFACE_MGMT: NetIface = NetIface {
    id: "mgmt",
    tap: "mgmt",
    mac: "02:DE:AD:BE:EF:01",
};

/// First fabric-facing network interface (jumbo frames).
pub(crate) const IFACE_FABRIC1: NetIface = NetIface {
    id: "fabric1",
    tap: "fabric1",
    mac: "02:CA:FE:BA:BE:01",
};

/// Second fabric-facing network interface (jumbo frames).
pub(crate) const IFACE_FABRIC2: NetIface = NetIface {
    id: "fabric2",
    tap: "fabric2",
    mac: "02:CA:FE:BA:BE:02",
};

/// All network interfaces in the order they are presented to the VM.
///
/// Used by backends to iterate over the interface set, and by tests to
/// verify uniqueness constraints on MACs, taps, and IDs.
pub(crate) const ALL_IFACES: [&NetIface; 3] = [&IFACE_MGMT, &IFACE_FABRIC1, &IFACE_FABRIC2];

// ── Cloud-hypervisor network tuning ──────────────────────────────────
//
// These constants are only consumed by the cloud-hypervisor backend
// (QEMU does not support setting MTU or virtio queue depth via the
// command line), but they live here alongside the shared interface
// descriptors so that all network configuration is co-located and the
// values are visible in one place.

/// MTU for the management network interface (standard Ethernet).
pub(crate) const MGMT_MTU: i32 = 1500;

/// MTU for fabric-facing network interfaces (jumbo frames).
pub(crate) const FABRIC_MTU: i32 = 9500;

/// Virtio queue depth for the management network interface.
pub(crate) const MGMT_QUEUE_SIZE: i32 = 512;

/// Virtio queue depth for fabric-facing network interfaces.
pub(crate) const FABRIC_QUEUE_SIZE: i32 = 8192;

// ── Device tuning ────────────────────────────────────────────────────

/// Virtio queue depth for the virtiofs filesystem device.
///
/// Used by both backends: cloud-hypervisor as `FsConfig.queue_size`,
/// QEMU as the `queue-size=` parameter on `vhost-user-fs-pci`.
pub(crate) const VIRTIOFS_QUEUE_SIZE: u32 = 1024;

/// Initial buffer capacity for vsock reader tasks.
///
/// Sized to hold the typical test stdout/stderr output without
/// reallocation.  Grows automatically if the output exceeds this.
pub(crate) const VSOCK_READER_CAPACITY: usize = 32_768;

// ── Timeouts ─────────────────────────────────────────────────────────

/// Duration to continue draining hypervisor events after a guest panic
/// is detected.
///
/// This gives the hypervisor time to emit subsequent lifecycle events
/// (e.g. `Shutdown`, `Deleted` for cloud-hypervisor; `SHUTDOWN` for
/// QEMU) that aid diagnosis of the panic's root cause.
pub(crate) const POST_PANIC_DRAIN_TIMEOUT: Duration = Duration::from_millis(500);

// ── Kernel command line ──────────────────────────────────────────────

/// Builds the guest kernel command line.
///
/// Both the cloud-hypervisor and QEMU backends pass this string to the
/// guest kernel (via `PayloadConfig.cmdline` and `-append` respectively).
/// Having a single builder ensures the two backends stay in sync and
/// prevents subtle divergence in the guest environment.
///
/// The command line includes:
///
/// - **IOMMU kernel support** -- always enabled (`iommu=on`,
///   `intel_iommu=on`, `amd_iommu=on`) so that the kernel's IOMMU
///   subsystem is initialised regardless of whether the hypervisor
///   presents a virtual IOMMU device.
/// - **VFIO no-IOMMU mode** -- enabled (`vfio.enable_unsafe_noiommu_mode=1`)
///   only when `iommu` is `false`.  When a vIOMMU is present, omitting
///   this parameter forces VFIO to use the IOMMU for DMA remapping,
///   which is the whole point of the vIOMMU test configuration.
/// - **Serial console** (`earlyprintk=ttyS0`, `console=ttyS0`).
/// - **Root filesystem** -- read-only virtiofs.
/// - **Hugepage reservation** for DPDK (conditional, based on
///   [`GuestHugePageConfig`]).
/// - **Vsock port assignments** for the init system's output channels.
/// - **Init binary path** and the test binary + name after `--`.
pub(crate) fn build_kernel_cmdline(
    vm_bin_path: &str,
    test_name: &str,
    vsock: &VsockAllocation,
    iommu: bool,
    guest_hugepages: &GuestHugePageConfig,
) -> String {
    let vsock_cmdline = vsock.kernel_cmdline_fragment();

    // When running without a vIOMMU, allow VFIO to operate in no-IOMMU
    // mode so that DPDK can still bind devices via vfio-pci.  When
    // running *with* a vIOMMU, omit this parameter so that VFIO is
    // forced to use the IOMMU — otherwise the no-IOMMU escape hatch
    // would undermine the DMA remapping test.
    let noiommu_fragment = if iommu {
        ""
    } else {
        "vfio.enable_unsafe_noiommu_mode=1 "
    };

    let hugepage_fragment = guest_hugepages.kernel_cmdline_fragment();

    format!(
        "iommu=on \
         intel_iommu=on \
         amd_iommu=on \
         {noiommu_fragment}\
         earlyprintk=ttyS0 \
         console=ttyS0 \
         ro \
         rootfstype=virtiofs \
         root=root \
         {hugepage_fragment}\
         {vsock_cmdline} \
         init={INIT_BINARY_PATH} \
         -- {vm_bin_path} {test_name} --exact --no-capture --format=terse",
    )
}

// ── Utility functions ────────────────────────────────────────────────

/// Reads an async byte stream to EOF and returns its contents as a
/// UTF-8 string.
///
/// Used by both backends' [`spawn_vsock_reader`] implementations after
/// accepting a connection.  The concrete stream type differs between
/// backends ([`tokio::net::UnixStream`] for cloud-hypervisor,
/// [`tokio_vsock::VsockStream`] for QEMU) but both implement
/// [`AsyncRead`](tokio::io::AsyncRead), so this function is generic
/// over the stream type.
///
/// On I/O error the read loop terminates early and returns whatever data
/// was collected up to that point.  Non-UTF-8 bytes are replaced via
/// [`String::from_utf8_lossy`].
///
/// [`spawn_vsock_reader`]: crate::backend::HypervisorBackend::spawn_vsock_reader
pub(crate) async fn read_vsock_stream(
    mut stream: impl tokio::io::AsyncRead + Unpin,
    label: &str,
) -> String {
    let mut buf = Vec::with_capacity(VSOCK_READER_CAPACITY);
    loop {
        match stream.read_buf(&mut buf).await {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) => {
                error!("error reading {label} vsock stream: {e}");
                break;
            }
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

/// Best-effort capture of a child process's stderr, logged at
/// appropriate levels.
///
/// Called when a child process (virtiofsd, QEMU, cloud-hypervisor, etc.)
/// fails during launch so that the developer can see the actual error
/// output instead of a generic socket timeout or connection-refused
/// message.
///
/// A short sleep (`100 ms`) gives the child time to flush its output
/// before we read.  A `2 s` timeout prevents blocking indefinitely if
/// the child's stderr pipe never reaches EOF.
///
/// If stderr is empty, a warning is logged.  If the read times out,
/// whatever partial data was collected is logged.
pub(crate) async fn drain_child_stderr(child: &mut tokio::process::Child, label: &str) {
    // Give the child a moment to flush its output.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let Some(mut stderr) = child.stderr.take() else {
        return;
    };

    let mut buf = String::with_capacity(4096);
    match tokio::time::timeout(Duration::from_secs(2), stderr.read_to_string(&mut buf)).await {
        Ok(Ok(_)) if !buf.is_empty() => {
            error!("{label} stderr (captured after launch failure):\n{buf}");
        }
        Ok(Ok(_)) => {
            warn!("{label} stderr was empty after launch failure");
        }
        Ok(Err(e)) => {
            warn!("failed to read {label} stderr: {e}");
        }
        Err(_) => {
            warn!("timed out reading {label} stderr");
            if !buf.is_empty() {
                error!("{label} stderr (partial, timed out):\n{buf}");
            }
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Default guest hugepage config used by tests that do not exercise
    /// page-size variation.
    const DEFAULT_HP: GuestHugePageConfig = GuestHugePageConfig::Allocate {
        size: GuestHugePageSize::Huge1G,
        count: 1,
    };

    // ── Kernel command line ──────────────────────────────────────────

    #[test]
    fn kernel_cmdline_includes_hugepage_reservation_for_1g() {
        let vsock = n_vm_protocol::VsockAllocation::with_defaults();
        let hp = GuestHugePageConfig::Allocate {
            size: GuestHugePageSize::Huge1G,
            count: 1,
        };
        let cmdline = build_kernel_cmdline("/test/bin", "my::test", &vsock, false, &hp);
        assert!(
            cmdline.contains("hugepages=1"),
            "cmdline should configure hugepage count: {cmdline}",
        );
        assert!(
            cmdline.contains("hugepagesz=1G"),
            "cmdline should configure hugepage size: {cmdline}",
        );
        assert!(
            cmdline.contains("default_hugepagesz=1G"),
            "cmdline should set default hugepage size: {cmdline}",
        );
    }

    #[test]
    fn kernel_cmdline_includes_hugepage_reservation_for_2m() {
        let vsock = n_vm_protocol::VsockAllocation::with_defaults();
        let hp = GuestHugePageConfig::Allocate {
            size: GuestHugePageSize::Huge2M,
            count: 512,
        };
        let cmdline = build_kernel_cmdline("/test/bin", "my::test", &vsock, false, &hp);
        assert!(
            cmdline.contains("hugepages=512"),
            "cmdline should configure hugepage count: {cmdline}",
        );
        assert!(
            cmdline.contains("hugepagesz=2M"),
            "cmdline should configure 2M hugepage size: {cmdline}",
        );
        assert!(
            cmdline.contains("default_hugepagesz=2M"),
            "cmdline should set default hugepage size: {cmdline}",
        );
    }

    #[test]
    fn kernel_cmdline_omits_hugepages_when_none() {
        let vsock = n_vm_protocol::VsockAllocation::with_defaults();
        let cmdline = build_kernel_cmdline(
            "/test/bin",
            "my::test",
            &vsock,
            false,
            &GuestHugePageConfig::None,
        );
        assert!(
            !cmdline.contains("hugepagesz"),
            "cmdline should not contain hugepagesz: {cmdline}",
        );
        assert!(
            !cmdline.contains("default_hugepagesz"),
            "cmdline should not contain default_hugepagesz: {cmdline}",
        );
    }

    #[test]
    fn kernel_cmdline_includes_init_binary() {
        let vsock = n_vm_protocol::VsockAllocation::with_defaults();
        let cmdline = build_kernel_cmdline("/test/bin", "my::test", &vsock, false, &DEFAULT_HP);
        assert!(
            cmdline.contains(&format!("init={INIT_BINARY_PATH}")),
            "cmdline should set init binary: {cmdline}",
        );
    }

    #[test]
    fn kernel_cmdline_passes_test_binary_and_name() {
        let vsock = n_vm_protocol::VsockAllocation::with_defaults();
        let cmdline = build_kernel_cmdline("/test/bin", "my::test", &vsock, false, &DEFAULT_HP);
        assert!(
            cmdline.contains("-- /test/bin my::test --exact"),
            "cmdline should pass test binary and name after '--': {cmdline}",
        );
    }

    #[test]
    fn kernel_cmdline_includes_vsock_parameters() {
        let vsock = n_vm_protocol::VsockAllocation::with_defaults();
        let fragment = vsock.kernel_cmdline_fragment();
        let cmdline = build_kernel_cmdline("/test/bin", "my::test", &vsock, false, &DEFAULT_HP);
        assert!(
            cmdline.contains(&fragment),
            "cmdline should contain vsock port parameters ({fragment}): {cmdline}",
        );
    }

    #[test]
    fn kernel_cmdline_enables_noiommu_mode_when_iommu_disabled() {
        let vsock = n_vm_protocol::VsockAllocation::with_defaults();
        let cmdline = build_kernel_cmdline("/test/bin", "my::test", &vsock, false, &DEFAULT_HP);
        assert!(
            cmdline.contains("vfio.enable_unsafe_noiommu_mode=1"),
            "cmdline should enable no-IOMMU mode when iommu is disabled: {cmdline}",
        );
    }

    #[test]
    fn kernel_cmdline_omits_noiommu_mode_when_iommu_enabled() {
        let vsock = n_vm_protocol::VsockAllocation::with_defaults();
        let cmdline = build_kernel_cmdline("/test/bin", "my::test", &vsock, true, &DEFAULT_HP);
        assert!(
            !cmdline.contains("noiommu"),
            "cmdline should NOT enable no-IOMMU mode when iommu is enabled: {cmdline}",
        );
    }

    #[test]
    fn kernel_cmdline_enables_iommu_kernel_support_always() {
        let vsock = n_vm_protocol::VsockAllocation::with_defaults();

        for iommu in [false, true] {
            let cmdline = build_kernel_cmdline("/test/bin", "my::test", &vsock, iommu, &DEFAULT_HP);
            assert!(
                cmdline.contains("iommu=on"),
                "cmdline should always enable iommu (iommu={iommu}): {cmdline}",
            );
            assert!(
                cmdline.contains("intel_iommu=on"),
                "cmdline should always enable intel_iommu (iommu={iommu}): {cmdline}",
            );
            assert!(
                cmdline.contains("amd_iommu=on"),
                "cmdline should always enable amd_iommu (iommu={iommu}): {cmdline}",
            );
        }
    }

    #[test]
    fn kernel_cmdline_configures_serial_console() {
        let vsock = n_vm_protocol::VsockAllocation::with_defaults();
        let cmdline = build_kernel_cmdline("/test/bin", "my::test", &vsock, false, &DEFAULT_HP);
        assert!(
            cmdline.contains("console=ttyS0"),
            "cmdline: {cmdline}",
        );
        assert!(
            cmdline.contains("earlyprintk=ttyS0"),
            "cmdline: {cmdline}",
        );
    }

    #[test]
    fn kernel_cmdline_uses_virtiofs_root() {
        let vsock = n_vm_protocol::VsockAllocation::with_defaults();
        let cmdline = build_kernel_cmdline("/test/bin", "my::test", &vsock, false, &DEFAULT_HP);
        assert!(
            cmdline.contains("rootfstype=virtiofs"),
            "cmdline: {cmdline}",
        );
        assert!(cmdline.contains("root=root"), "cmdline: {cmdline}");
    }

    #[test]
    fn kernel_cmdline_passes_no_capture_and_terse_format() {
        let vsock = n_vm_protocol::VsockAllocation::with_defaults();
        let cmdline = build_kernel_cmdline("/test/bin", "my::test", &vsock, false, &DEFAULT_HP);
        assert!(
            cmdline.contains("--no-capture"),
            "cmdline should pass --no-capture: {cmdline}",
        );
        assert!(
            cmdline.contains("--format=terse"),
            "cmdline should pass --format=terse: {cmdline}",
        );
    }

    // ── Network interfaces ──────────────────────────────────────────

    #[test]
    fn all_interfaces_have_unique_mac_addresses() {
        let macs: Vec<&str> = ALL_IFACES.iter().map(|i| i.mac).collect();
        let mut deduped = macs.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(
            macs.len(),
            deduped.len(),
            "MAC addresses must be unique: {macs:?}",
        );
    }

    #[test]
    fn all_interfaces_have_unique_tap_names() {
        let taps: Vec<&str> = ALL_IFACES.iter().map(|i| i.tap).collect();
        let mut deduped = taps.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(
            taps.len(),
            deduped.len(),
            "TAP names must be unique: {taps:?}",
        );
    }

    #[test]
    fn all_interfaces_have_unique_ids() {
        let ids: Vec<&str> = ALL_IFACES.iter().map(|i| i.id).collect();
        let mut deduped = ids.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(
            ids.len(),
            deduped.len(),
            "interface IDs must be unique: {ids:?}",
        );
    }

    #[test]
    fn interface_count_is_three() {
        assert_eq!(
            ALL_IFACES.len(),
            3,
            "expected exactly 3 interfaces (mgmt + 2 fabric)",
        );
    }

    // ── VM topology ─────────────────────────────────────────────────

    #[test]
    fn topology_multiplies_to_vcpu_count() {
        let total =
            VM_SOCKETS * VM_DIES_PER_PACKAGE * VM_CORES_PER_DIE * VM_THREADS_PER_CORE;
        assert_eq!(
            total, VM_VCPUS,
            "topology ({VM_SOCKETS}S × {VM_DIES_PER_PACKAGE}D × \
             {VM_CORES_PER_DIE}C × {VM_THREADS_PER_CORE}T = {total}) \
             must equal VM_VCPUS ({VM_VCPUS})",
        );
    }

    #[test]
    fn default_config_passes_memory_alignment_validation() {
        VmConfig::default()
            .validate_memory_alignment()
            .expect("default VmConfig should pass memory alignment validation");
    }

    #[test]
    fn all_host_page_sizes_are_memory_aligned() {
        for host_page_size in [
            HostPageSize::Standard,
            HostPageSize::Huge2M,
            HostPageSize::Huge1G,
        ] {
            let config = VmConfig {
                host_page_size,
                ..VmConfig::default()
            };
            config
                .validate_memory_alignment()
                .unwrap_or_else(|e| panic!("{host_page_size:?}: {e}"));
        }
    }

    #[test]
    fn guest_hugepages_exceeding_memory_fails_validation() {
        let config = VmConfig {
            guest_hugepages: GuestHugePageConfig::Allocate {
                size: GuestHugePageSize::Huge1G,
                count: 100,
            },
            ..VmConfig::default()
        };
        assert!(
            config.validate_memory_alignment().is_err(),
            "100 × 1G hugepages should exceed VM memory",
        );
    }

    #[test]
    fn guest_hugepages_none_passes_validation() {
        let config = VmConfig {
            guest_hugepages: GuestHugePageConfig::None,
            ..VmConfig::default()
        };
        config
            .validate_memory_alignment()
            .expect("GuestHugePageConfig::None should always pass validation");
    }

    #[test]
    fn memory_mib_and_bytes_are_consistent() {
        assert_eq!(
            VM_MEMORY_BYTES,
            (VM_MEMORY_MIB as i64) * 1024 * 1024,
            "VM_MEMORY_BYTES and VM_MEMORY_MIB must be consistent",
        );
    }
}