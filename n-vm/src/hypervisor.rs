//! Cloud-hypervisor event monitoring and JSON stream decoding.
//!
//! This module provides types for deserializing the event stream emitted by
//! [cloud-hypervisor](https://github.com/cloud-hypervisor/cloud-hypervisor)
//! via its `--event-monitor` file descriptor, along with an async codec for
//! reading those events incrementally from a pipe.

use std::collections::BTreeMap;
use std::time::Duration;

use serde::Deserialize;
use serde_json::StreamDeserializer;
use tokio_stream::StreamExt;
use tokio_util::bytes::{Buf, BytesMut};
use tracing::error;

// ── Hypervisor event types ───────────────────────────────────────────

/// The component that emitted a hypervisor event.
#[derive(Debug, Copy, Clone, Deserialize)]
pub enum Source {
    /// The virtual machine itself.
    #[serde(rename = "vm")]
    Vm,
    /// The virtual machine monitor (VMM) process.
    #[serde(rename = "vmm")]
    Vmm,
    /// The guest operating system.
    #[serde(rename = "guest")]
    Guest,
    /// A virtio device backend.
    #[serde(rename = "virtio-device")]
    VirtioDevice,
}

/// The type of hypervisor lifecycle event.
#[derive(Debug, Copy, Clone, Deserialize)]
pub enum EventType {
    /// The VMM is starting up.
    #[serde(rename = "starting")]
    Starting,
    /// The VM is booting (kernel loaded, about to execute).
    #[serde(rename = "booting")]
    Booting,
    /// The VM has finished booting.
    #[serde(rename = "booted")]
    Booted,
    /// A virtio device has been activated.
    #[serde(rename = "activated")]
    Activated,
    /// The VM has been deleted.
    #[serde(rename = "deleted")]
    Deleted,
    /// The VM or VMM has shut down cleanly.
    #[serde(rename = "shutdown")]
    Shutdown,
    /// The guest kernel panicked.
    #[serde(rename = "panic")]
    Panic,
}

/// A single event from the cloud-hypervisor event monitor.
///
/// Events are emitted as newline-delimited JSON objects on the file descriptor
/// passed via `--event-monitor fd=N`.
#[derive(Debug, Clone, Deserialize)]
pub struct Event {
    /// Time elapsed since the VMM process started.
    pub timestamp: Duration,
    /// Which component emitted the event.
    pub source: Source,
    /// The lifecycle event that occurred.
    pub event: EventType,
    /// Optional key-value properties attached to the event.
    #[serde(deserialize_with = "deserialize_null_default")]
    pub properties: BTreeMap<String, String>,
}

fn deserialize_null_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    T: Default + Deserialize<'de>,
    D: serde::Deserializer<'de>,
{
    let opt = Option::deserialize(deserializer)?;
    Ok(opt.unwrap_or_default())
}

// ── Async JSON stream decoder ────────────────────────────────────────

/// A [`tokio_util::codec::Decoder`] that incrementally deserializes
/// concatenated JSON [`Event`] values from a byte stream.
///
/// This is used to parse the cloud-hypervisor event monitor output, which
/// consists of concatenated JSON objects written to a pipe.
///
/// The previous implementation carried a phantom lifetime and generic type
/// parameter that were never used — the `Decoder` impl was always
/// monomorphised for [`Event`].  This version is a simple unit struct.
#[derive(Debug, Default)]
pub struct AsyncJsonStreamDecoder;

impl AsyncJsonStreamDecoder {
    pub fn new() -> Self {
        Self
    }
}

/// Errors that can occur while decoding a JSON stream.
#[derive(Debug, thiserror::Error)]
pub enum AsyncJsonStreamError {
    /// A JSON deserialization error.
    #[error("JSON deserialization error: {0}")]
    Json(#[from] serde_json::Error),
    /// An I/O error from the underlying reader.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl tokio_util::codec::Decoder for AsyncJsonStreamDecoder {
    type Item = Event;
    type Error = AsyncJsonStreamError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let buf = src.as_ref().to_vec();
        let mut stream: StreamDeserializer<'_, serde_json::de::SliceRead<'_>, Event> =
            serde_json::Deserializer::from_slice(&buf).into_iter::<Event>();
        let next = stream.next();
        let bytes_consumed = stream.byte_offset();
        match next {
            Some(Ok(value)) => {
                src.advance(bytes_consumed);
                Ok(Some(value))
            }
            Some(Err(err)) => Err(AsyncJsonStreamError::Json(err)),
            None => Ok(None),
        }
    }
}

// ── Hypervisor event watcher ─────────────────────────────────────────

/// Consumes the hypervisor event stream and returns the collected events along
/// with a success verdict.
///
/// Returns `(events, true)` on a clean VMM shutdown, or `(events, false)` if a
/// guest panic is detected or the stream ends unexpectedly.
pub async fn watch(receiver: tokio::net::unix::pipe::Receiver) -> (Vec<Event>, bool) {
    let decoder = AsyncJsonStreamDecoder::new();

    let mut reader = tokio_util::codec::FramedRead::new(receiver, decoder);
    let mut hlog = Vec::with_capacity(32);

    let mut success = true;

    loop {
        let event = reader.next().await;
        match event {
            Some(Ok(value)) => {
                hlog.push(value.clone());
                match (value.source, value.event) {
                    (Source::Vmm, EventType::Shutdown) => {
                        return (hlog, success);
                    }
                    (Source::Guest, EventType::Panic) => {
                        success = false;
                        break;
                    }
                    _ => {}
                };
            }
            Some(Err(e)) => {
                error!("{e:#?}");
            }
            None => {
                break;
            }
        }
    }
    (hlog, success)
}