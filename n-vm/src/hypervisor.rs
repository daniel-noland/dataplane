//! Cloud-hypervisor event monitoring and JSON stream decoding.
//!
//! This module provides types for deserializing the event stream emitted by
//! [cloud-hypervisor](https://github.com/cloud-hypervisor/cloud-hypervisor)
//! via its `--event-monitor` file descriptor, along with an async codec for
//! reading those events incrementally from a pipe.
//!
//! The [`watch`] function consumes the event stream and returns a
//! [`HypervisorVerdict`] indicating whether the VM shut down cleanly.

use std::collections::BTreeMap;
use std::time::Duration;

use serde::Deserialize;
use serde_json::StreamDeserializer;
use tokio_stream::StreamExt;
use tokio_util::bytes::{Buf, BytesMut};
use tracing::warn;

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

/// Deserializes `null` JSON values as `T::default()` instead of failing.
fn deserialize_null_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    T: Default + Deserialize<'de>,
    D: serde::Deserializer<'de>,
{
    let opt = Option::deserialize(deserializer)?;
    Ok(opt.unwrap_or_default())
}

// ── Hypervisor verdict ───────────────────────────────────────────────

/// Verdict from the hypervisor event watcher indicating how the VM
/// session ended.
///
/// This replaces a bare `bool` return, making call sites self-documenting
/// and preventing accidental inversion of the success/failure logic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HypervisorVerdict {
    /// The VMM emitted a clean `Shutdown` event with no preceding guest
    /// panic or event-stream errors.
    CleanShutdown,
    /// The VM session ended abnormally — a guest panic was detected, the
    /// event stream contained deserialization errors, or the stream ended
    /// without a clean shutdown event.
    Failure,
}

impl HypervisorVerdict {
    /// Returns `true` if the VM shut down cleanly.
    #[must_use]
    pub fn is_success(self) -> bool {
        matches!(self, Self::CleanShutdown)
    }
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
    /// Creates a new decoder instance.
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
        // Scope the immutable borrow of `src` (via `as_ref()`) so that we
        // can call `src.advance()` afterward without a borrow conflict.
        let (next, bytes_consumed) = {
            let mut stream: StreamDeserializer<'_, serde_json::de::SliceRead<'_>, Event> =
                serde_json::Deserializer::from_slice(src.as_ref()).into_iter::<Event>();
            let next = stream.next();
            (next, stream.byte_offset())
        };
        match next {
            Some(Ok(value)) => {
                src.advance(bytes_consumed);
                Ok(Some(value))
            }
            // An EOF error means the buffer contains a partial JSON object
            // that is still being written to the pipe.  Return `Ok(None)`
            // to tell the framing layer to wait for more data rather than
            // treating it as a fatal parse error.
            Some(Err(err))
                if err.classify() == serde_json::error::Category::Eof =>
            {
                Ok(None)
            }
            Some(Err(err)) => Err(AsyncJsonStreamError::Json(err)),
            None => Ok(None),
        }
    }
}

// ── Hypervisor event watcher ─────────────────────────────────────────

/// Consumes the hypervisor event stream and returns the collected events
/// along with a [`HypervisorVerdict`].
///
/// Returns [`HypervisorVerdict::CleanShutdown`] if the VMM emits a clean
/// `Shutdown` event with no preceding errors, or
/// [`HypervisorVerdict::Failure`] if a guest panic is detected, the event
/// stream contains deserialization errors, or the stream ends without a
/// clean shutdown.
pub async fn watch(
    receiver: tokio::net::unix::pipe::Receiver,
) -> (Vec<Event>, HypervisorVerdict) {
    let decoder = AsyncJsonStreamDecoder::new();

    let mut reader = tokio_util::codec::FramedRead::new(receiver, decoder);
    let mut hlog = Vec::with_capacity(32);

    let mut clean = true;

    loop {
        let event = reader.next().await;
        match event {
            Some(Ok(value)) => {
                hlog.push(value.clone());
                match (value.source, value.event) {
                    (Source::Vmm, EventType::Shutdown) => {
                        let verdict = if clean {
                            HypervisorVerdict::CleanShutdown
                        } else {
                            HypervisorVerdict::Failure
                        };
                        return (hlog, verdict);
                    }
                    (Source::Guest, EventType::Panic) => {
                        break;
                    }
                    _ => {}
                };
            }
            Some(Err(e)) => {
                // Deserialization errors may hide critical events (e.g.
                // a guest panic encoded in a malformed JSON object), so
                // they downgrade the verdict to Failure.
                warn!("hypervisor event deserialization error (marking as failure): {e:#?}");
                clean = false;
            }
            None => {
                break;
            }
        }
    }
    (hlog, HypervisorVerdict::Failure)
}