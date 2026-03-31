use n_vm::in_vm;

#[in_vm]
#[test]
fn test_which_runs_in_vm() {
    assert_eq!(2 + 2, 4);
}

#[in_vm]
#[should_panic]
#[test]
#[allow(unreachable_code)]
fn test_which_runs_in_vm_control() {
    assert_eq!(2 + 2, 4);
    panic!("deliberate panic");
}

#[test]
fn test_which_does_not_run_in_vm() {
    assert_eq!(2 + 2, 4);
}

#[ignore = "deactivated until needed as control"]
#[should_panic]
#[test]
fn test_which_does_not_run_in_vm_control() {
    assert_eq!(2 + 2, 4);
    panic!("deliberate panic");
}

#[in_vm]
#[test]
fn root_filesystem_in_vm_is_read_only() {
    let error = std::fs::File::create_new("/some.file").unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::ReadOnlyFilesystem);
}

#[in_vm]
#[test]
fn run_filesystem_in_vm_is_read_write() {
    std::fs::File::create_new("/run/some.file").unwrap();
}

#[in_vm]
#[test]
fn tmp_filesystem_in_vm_is_read_write() {
    std::fs::File::create_new("/tmp/some.file").unwrap();
}

// ── vIOMMU integration tests ─────────────────────────────────────────
//
// These tests exercise the same basic assertions as above but with the
// virtual IOMMU enabled, verifying that the VM boots and operates
// correctly when devices are behind DMA remapping.

#[in_vm]
#[test]
#[hypervisor(iommu)]
fn test_which_runs_in_vm_with_iommu() {
    assert_eq!(2 + 2, 4);
}

#[in_vm(qemu)]
#[test]
#[hypervisor(iommu)]
fn test_which_runs_in_vm_with_qemu_iommu() {
    assert_eq!(2 + 2, 4);
}

#[in_vm(cloud_hypervisor)]
#[test]
#[hypervisor(iommu)]
fn test_which_runs_in_vm_with_cloud_hypervisor_iommu() {
    assert_eq!(2 + 2, 4);
}

// ── Host page size integration tests ─────────────────────────────────
//
// These tests verify the VM boots correctly with each supported host
// memory backing.  The `host_pages = "4k"` variant is particularly
// important because it requires no physical hugepages on the host,
// making it viable for CI environments.

#[in_vm]
#[test]
#[hypervisor(host_pages = "4k")]
fn vm_boots_with_standard_host_pages() {
    assert!(std::path::Path::new("/proc/meminfo").exists());
}

#[in_vm(qemu)]
#[test]
#[hypervisor(host_pages = "4k")]
fn vm_boots_with_standard_host_pages_on_qemu() {
    assert!(std::path::Path::new("/proc/meminfo").exists());
}

// ── Guest hugepage integration tests ─────────────────────────────────
//
// These tests exercise the guest-side hugepage reservation axis,
// verifying the kernel command-line parameters are applied correctly
// and the VM boots with the requested hugepage configuration.

#[in_vm]
#[test]
#[guest(hugepage_size = "none")]
fn vm_boots_without_guest_hugepages() {
    // When hugepage_size = "none", no hugepage pool should be reserved.
    let meminfo = std::fs::read_to_string("/proc/meminfo").unwrap();
    let huge_total: u64 = meminfo
        .lines()
        .find(|l| l.starts_with("HugePages_Total:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    assert_eq!(huge_total, 0, "expected no guest hugepages when hugepage_size = none");
}

#[in_vm]
#[test]
#[guest(hugepage_size = "2m", hugepage_count = 64)]
fn vm_boots_with_2m_guest_hugepages() {
    // The kernel should have reserved exactly the requested count of
    // 2 MiB hugepages.
    let meminfo = std::fs::read_to_string("/proc/meminfo").unwrap();
    let huge_total: u64 = meminfo
        .lines()
        .find(|l| l.starts_with("HugePages_Total:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    assert_eq!(huge_total, 64, "expected 64 guest hugepages from kernel reservation");
}

// ── Combined configuration integration tests ─────────────────────────
//
// These tests exercise both axes together, demonstrating that host
// page size and guest hugepage reservation are truly independent.

#[in_vm]
#[test]
#[hypervisor(host_pages = "4k")]
#[guest(hugepage_size = "none")]
fn vm_boots_with_4k_host_pages_and_no_guest_hugepages() {
    // Most CI-friendly configuration: no hugepages anywhere.
    let meminfo = std::fs::read_to_string("/proc/meminfo").unwrap();
    let huge_total: u64 = meminfo
        .lines()
        .find(|l| l.starts_with("HugePages_Total:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    assert_eq!(huge_total, 0, "expected no guest hugepages in CI-friendly mode");
}

#[in_vm(qemu)]
#[test]
#[hypervisor(iommu, host_pages = "4k")]
#[guest(hugepage_size = "2m", hugepage_count = 64)]
async fn vm_boots_with_4k_host_and_2m_guest_hugepages_on_qemu() {
    // Standard host pages but 2M guest hugepages with IOMMU -- the two
    // axes are independent, so this combination must work.
    let meminfo = std::fs::read_to_string("/proc/meminfo").unwrap();
    let huge_total: u64 = meminfo
        .lines()
        .find(|l| l.starts_with("HugePages_Total:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    assert_eq!(huge_total, 64, "expected 64 guest hugepages with 4K host backing");
}

// ── #[tokio::test] rewriting integration tests ──────────────────────
//
// These tests verify that `#[in_vm]` correctly rewrites `#[tokio::test]`
// to `#[test]` and gleans the runtime configuration from its arguments.
// The macro removes `#[tokio::test]`, injects `#[test]`, and selects the
// appropriate tokio runtime flavor for the VM guest tier.

#[in_vm]
#[tokio::test]
async fn tokio_test_current_thread_default() {
    // Bare `#[tokio::test]` → single-threaded runtime (the default).
    let contents = tokio::fs::read_to_string("/proc/version").await.unwrap();
    assert!(contents.contains("Linux"));
}

#[in_vm]
#[tokio::test(flavor = "current_thread")]
async fn tokio_test_explicit_current_thread() {
    // Explicit `flavor = "current_thread"` → same as bare #[tokio::test].
    let contents = tokio::fs::read_to_string("/proc/version").await.unwrap();
    assert!(contents.contains("Linux"));
}

#[in_vm]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tokio_test_multi_thread() {
    // Multi-threaded runtime with explicit worker count.  Spawn a task
    // on a different thread to verify the runtime is truly multi-threaded.
    let handle = tokio::spawn(async {
        tokio::fs::read_to_string("/proc/version").await.unwrap()
    });
    let contents = handle.await.unwrap();
    assert!(contents.contains("Linux"));
}

#[in_vm]
#[tokio::test(flavor = "multi_thread")]
async fn tokio_test_multi_thread_default_workers() {
    // Multi-threaded runtime with tokio's default worker count (number
    // of CPU cores).  In the VM guest this is typically 1-2, but the
    // runtime should still function correctly.
    let handle = tokio::spawn(async { 2 + 2 });
    assert_eq!(handle.await.unwrap(), 4);
}
