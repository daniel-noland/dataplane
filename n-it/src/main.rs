use std::convert::Infallible;
use std::process;
use std::sync::atomic::{AtomicUsize, Ordering};

use n_vm_protocol::INIT_SYSTEM_VSOCK_PORT;
use tokio_vsock::VMADDR_CID_HOST;

// NOTE: `utils` must be declared before modules that use the `fatal!` macro.
#[macro_use]
mod utils;

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
        .unwrap();
    runtime.block_on(async {
        eprintln!("init system runtime started: connecting to tracing vsock");
        let tracing_addr = vsock::VsockAddr::new(VMADDR_CID_HOST, INIT_SYSTEM_VSOCK_PORT);
        let tracing_vsock = VsockWriter::new(
            vsock::VsockStream::connect(&tracing_addr).unwrap(),
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