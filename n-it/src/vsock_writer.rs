use std::io::Write;
use std::sync::{Mutex, MutexGuard};

use tracing_subscriber::fmt::MakeWriter;

pub struct VsockWriter(Mutex<vsock::VsockStream>);

impl VsockWriter {
    pub fn new(stream: vsock::VsockStream) -> Self {
        Self(Mutex::new(stream))
    }
}

pub struct VsockWriterGuard<'a>(MutexGuard<'a, vsock::VsockStream>);

impl Write for VsockWriterGuard<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

impl<'a> MakeWriter<'a> for VsockWriter {
    type Writer = VsockWriterGuard<'a>;

    fn make_writer(&'a self) -> Self::Writer {
        VsockWriterGuard(self.0.lock().unwrap_or_else(|e| e.into_inner()))
    }
}