use std::collections::BTreeMap;
use std::time::Duration;

use serde::Deserialize;
use serde_json::StreamDeserializer;
use tokio_stream::StreamExt;
use tokio_util::bytes::{Buf, BytesMut};
use tracing::error;

// ── Hypervisor event types ───────────────────────────────────────────

#[derive(Debug, Copy, Clone, Deserialize)]
pub enum Source {
    #[serde(rename = "vm")]
    Vm,
    #[serde(rename = "vmm")]
    Vmm,
    #[serde(rename = "guest")]
    Guest,
    #[serde(rename = "virtio-device")]
    VirtioDevice,
}

#[derive(Debug, Copy, Clone, Deserialize)]
pub enum EventType {
    #[serde(rename = "starting")]
    Starting,
    #[serde(rename = "booting")]
    Booting,
    #[serde(rename = "booted")]
    Booted,
    #[serde(rename = "activated")]
    Activated,
    #[serde(rename = "deleted")]
    Deleted,
    #[serde(rename = "shutdown")]
    Shutdown,
    #[serde(rename = "panic")]
    Panic,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Event {
    pub timestamp: Duration,
    pub source: Source,
    pub event: EventType,
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

pub struct AsyncJsonStreamDecoder<'a, T: Deserialize<'a>> {
    _phantom: std::marker::PhantomData<&'a T>,
}

impl<'a, T> AsyncJsonStreamDecoder<'a, T>
where
    T: Deserialize<'a>,
{
    pub fn new() -> Self {
        Self {
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<'a, T> Default for AsyncJsonStreamDecoder<'a, T>
where
    T: Deserialize<'a>,
{
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub enum AsyncJsonStreamError {
    Json(serde_json::Error),
    Io(std::io::Error),
}

impl From<std::io::Error> for AsyncJsonStreamError {
    fn from(err: std::io::Error) -> Self {
        AsyncJsonStreamError::Io(err)
    }
}

impl<'a> tokio_util::codec::Decoder for AsyncJsonStreamDecoder<'a, Event>
where
    Self: 'a,
{
    type Item = Event;
    type Error = AsyncJsonStreamError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let x = src.as_ref().to_vec();
        let mut des: StreamDeserializer<'_, serde_json::de::SliceRead<'_>, Event> =
            serde_json::Deserializer::from_slice(&x).into_iter::<Event>();
        let next = des.next();
        let bytes_consumed = des.byte_offset();
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