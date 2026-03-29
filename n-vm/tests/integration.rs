use n_vm::in_vm;

#[test]
#[in_vm]
fn test_which_runs_in_vm() {
    assert_eq!(2 + 2, 4);
}

#[should_panic]
#[test]
#[allow(unreachable_code)]
#[in_vm]
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

#[test]
#[in_vm]
fn root_filesystem_in_vm_is_read_only() {
    let error = std::fs::File::create_new("/some.file").unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::ReadOnlyFilesystem);
}

#[test]
#[in_vm]
fn run_filesystem_in_vm_is_read_write() {
    std::fs::File::create_new("/run/some.file").unwrap();
}

#[test]
#[in_vm]
fn tmp_filesystem_in_vm_is_read_write() {
    std::fs::File::create_new("/tmp/some.file").unwrap();
}
