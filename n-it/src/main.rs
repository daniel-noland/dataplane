//! Minimal init system for the `n-vm` test infrastructure.
//!
//! This binary runs as **PID 1** inside a cloud-hypervisor VM booted by
//! [`n_vm::run_in_vm`].  Its responsibilities are:
//!
//! 1. **Mount essential filesystems** — `/proc`, `/sys`, `/tmp`, `/run`, and
//!    `/sys/fs/cgroup` with appropriate security flags.
//! 2. **Spawn the test binary** as a child process with the `IN_VM=YES`
//!    environment variable, causing the `#[in_vm]` macro to execute the test
//!    body directly.
//! 3. **Forward signals** — benign signals (SIGHUP, SIGUSR1, etc.) are
//!    forwarded to the test process; failure signals (SIGINT, SIGPIPE, etc.)
//!    are forwarded and also mark the test as failed.
//! 4. **Reap orphaned processes** — after the test exits, any remaining child
//!    processes are terminated with SIGTERM.  Leaked processes are treated as
//!    a test failure.
//! 5. **Stream tracing data** back to the host via a vsock connection so that
//!    the container tier can collect init system logs.
//! 6. **Clean shutdown** — unmount filesystems, sync, and power off the VM
//!    (or abort on failure so the hypervisor detects a guest panic).

use std::convert::Infallible;
use std::process;
use std::sync::atomic::{AtomicUsize, Ordering};

use n_vm_protocol::VsockChannel;
use tokio_vsock::VMADDR_CID_HOST;

// NOTE: `utils` must be declared before modules that use the `fatal!` macro.
#[macro_use]
mod utils;

mod child;
mod mount;

mod init;
mod vsock_writer;

use init::InitSystem;
use vsock_writer::VsockWriter;

fn main() -> Infallible {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .thread_name_fn(|| {
            static ATOMIC_ID: AtomicUsize = AtomicUsize::new(0);
            let id = ATOMIC_ID.fetch_add(1, Ordering::SeqCst);
            format!("init-{}", id)
        })
        .max_blocking_threads(1)
        .build()
        .unwrap_or_else(|e| {
            eprintln!("FATAL: failed to build tokio runtime for init system: {e}");
            std::process::abort();
        });
    runtime.block_on(async {
        eprintln!("init system runtime started: connecting to tracing vsock");
        let tracing_addr = vsock::VsockAddr::new(VMADDR_CID_HOST, VsockChannel::INIT_TRACE.port);
        let tracing_vsock = VsockWriter::new(
            vsock::VsockStream::connect(&tracing_addr).unwrap_or_else(|e| {
                eprintln!("FATAL: failed to connect tracing vsock to host: {e}");
                std::process::abort();
            }),
        );
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_thread_ids(false)
            .with_thread_names(true)
            .with_line_number(true)
            .with_target(false)
            .with_writer(tracing_vsock)
            .with_file(true)
            .init();

        let _init_span = tracing::span!(tracing::Level::INFO, "init");
        let _guard = _init_span.enter();
        const INIT_PID: u32 = 1;
        if process::id() != INIT_PID {
            fatal!("this program must be run as PID {INIT_PID} (init process)");
        }
        InitSystem::run().await
    })
}