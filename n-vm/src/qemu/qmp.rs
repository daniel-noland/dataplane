// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! QEMU Machine Protocol (QMP) client.
//!
//! QMP is a JSON-based protocol that QEMU exposes over a Unix socket for
//! machine lifecycle control and event monitoring.  This module provides a
//! minimal, purpose-built client covering only the operations needed by
//! the [`Qemu`](super::Qemu) hypervisor backend:
//!
//! 1. **Connection and negotiation** -- connect to the QMP socket, receive
//!    the greeting, and enter command mode via `qmp_capabilities`.
//! 2. **Command execution** -- send commands (fire-and-forget) for
//!    best-effort shutdown (`system_powerdown`, `quit`).
//! 3. **Event monitoring** -- read and deserialize async QMP events for
//!    the event watcher task.
//!
//! # Protocol overview
//!
//! ```text
//! Client                                QEMU
//!   |                                     |
//!   |<--- {"QMP": {"version": ...}} ------|  (greeting)
//!   |---- {"execute": "qmp_capabilities"} -->|  (negotiate)
//!   |<--- {"return": {}} ----------------|  (success)
//!   |                                     |
//!   |  ... command mode active ...        |
//!   |                                     |
//!   |<--- {"event": "SHUTDOWN", ...} ----|  (async event)
//!   |---- {"execute": "quit"} ------------>|  (command)
//!   |<--- {"return": {}} ----------------|  (response)
//! ```
//!
//! After negotiation, the socket carries a mix of **responses** (to
//! commands) and **async events** (lifecycle transitions).  Since the
//! test infrastructure's shutdown path is best-effort and runs after the
//! event watcher has finished, the [`QmpWriter`] sends commands without
//! waiting for responses.
//!
//! # Socket split
//!
//! After negotiation, [`QmpConnection::into_split`] produces:
//!
//! - A [`QmpWriter`] that goes into the
//!   [`QemuController`](super::QemuController) for lifecycle commands.
//! - A [`QmpEventStream`] that goes into the background event-watcher
//!   task.
//!
//! The writer sends commands fire-and-forget (no response reading).  The
//! event stream consumes everything from the read half, discarding
//! command responses and yielding only [`QmpEvent`]s.  This avoids the
//! need for a multiplexer while keeping the API simple.

use std::path::Path;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tracing::{debug, trace, warn};

use super::error::QemuError;

// ── QMP wire types ───────────────────────────────────────────────────

/// The initial greeting sent by QEMU when a QMP client connects.
///
/// ```text
/// {"QMP": {"version": {"qemu": {"major": 9, ...}, ...}, "capabilities": ["oob"]}}
/// ```
#[derive(Debug, Deserialize)]
pub(crate) struct QmpGreeting {
    /// The `"QMP"` envelope.
    #[serde(rename = "QMP")]
    pub qmp: QmpGreetingInner,
}

/// Contents of the QMP greeting envelope.
#[derive(Debug, Deserialize)]
pub(crate) struct QmpGreetingInner {
    /// QEMU version information.
    pub version: QmpVersion,
    /// Server-advertised capabilities.
    #[serde(default)]
    #[allow(dead_code, reason = "deserialized from QMP greeting; used in tests")]
    pub capabilities: Vec<String>,
}

/// QEMU version information from the QMP greeting.
#[derive(Debug, Deserialize)]
pub(crate) struct QmpVersion {
    /// Structured QEMU version numbers.
    pub qemu: QmpVersionNumbers,
    /// Package version string (distribution-specific).
    #[serde(default)]
    pub package: String,
}

/// Structured QEMU version numbers.
#[derive(Debug, Deserialize)]
pub(crate) struct QmpVersionNumbers {
    /// Major version.
    pub major: u32,
    /// Minor version.
    pub minor: u32,
    /// Micro (patch) version.
    pub micro: u32,
}

/// A QMP command to send to QEMU.
#[derive(Debug, Serialize)]
struct QmpCommand<'a> {
    execute: &'a str,
}

/// A message received from the QMP socket after capability negotiation.
///
/// QMP interleaves three kinds of messages on the same socket:
///
/// - **Return** -- successful response to a command.
/// - **Error** -- failed response to a command.
/// - **Event** -- unsolicited lifecycle event.
///
/// Uses `#[serde(untagged)]` because the three forms are distinguished
/// by their top-level JSON key (`"return"`, `"error"`, `"event"`) rather
/// than by an explicit tag field.  Variant order matters: serde tries
/// each in declaration order, so `Return` (most common after commands)
/// comes first.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub(crate) enum QmpMessage {
    /// Successful command response.
    Return {
        /// The return value (usually `{}`).
        #[serde(rename = "return")]
        _value: serde_json::Value,
    },
    /// An async lifecycle event from QEMU.
    Event(QmpEvent),
    /// Failed command response.
    Error {
        /// The error details.
        error: QmpErrorInfo,
    },
}

/// Error details from a failed QMP command.
#[derive(Debug, Deserialize)]
pub(crate) struct QmpErrorInfo {
    /// Error class (e.g. `"GenericError"`).
    pub class: String,
    /// Human-readable error description.
    pub desc: String,
}

/// An async event from QEMU's QMP socket.
///
/// Events are sent unsolicited whenever a lifecycle transition occurs
/// (shutdown, reset, guest panic, device changes, etc.).
///
/// The [`Display`](std::fmt::Display) implementation produces a concise
/// one-line representation suitable for diagnostic output, showing the
/// event name followed by its data payload (if present).
#[derive(Debug, Clone, Deserialize)]
pub struct QmpEvent {
    /// Event name (e.g. `"SHUTDOWN"`, `"GUEST_PANICKED"`, `"RESET"`).
    pub event: String,
    /// Event-specific data payload (may be `null` or absent).
    #[serde(default)]
    pub data: serde_json::Value,
    /// QEMU-provided timestamp (`{"seconds": N, "microseconds": M}`).
    #[serde(default)]
    pub timestamp: serde_json::Value,
}

impl std::fmt::Display for QmpEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.event)?;
        if !self.data.is_null() {
            write!(f, " {}", self.data)?;
        }
        Ok(())
    }
}

// ── QMP connection ───────────────────────────────────────────────────

/// An established QMP connection that has completed capability
/// negotiation and is ready for command mode.
///
/// Created by [`QmpConnection::connect`], this type is consumed by
/// [`into_split`](Self::into_split) to produce a [`QmpWriter`] (for
/// sending commands) and a [`QmpEventStream`] (for reading events).
pub(crate) struct QmpConnection {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
}

impl QmpConnection {
    /// Connects to the QMP socket at `path`, reads the greeting, and
    /// negotiates capabilities.
    ///
    /// After this returns successfully, the connection is in command mode
    /// and ready to send commands or read events.
    ///
    /// # Errors
    ///
    /// Returns [`QemuError`] if the connection, greeting, or negotiation
    /// fails.
    pub async fn connect(path: impl AsRef<Path>) -> Result<Self, QemuError> {
        let stream = UnixStream::connect(path.as_ref())
            .await
            .map_err(QemuError::QmpConnect)?;

        let (read_half, write_half) = stream.into_split();
        let mut reader = BufReader::new(read_half);
        let mut writer = write_half;

        // ── Phase 1: read the QMP greeting ───────────────────────────
        let greeting = read_line_json::<QmpGreeting>(&mut reader).await?;
        debug!(
            "QMP greeting: QEMU {}.{}.{} (package: {:?})",
            greeting.qmp.version.qemu.major,
            greeting.qmp.version.qemu.minor,
            greeting.qmp.version.qemu.micro,
            greeting.qmp.version.package,
        );

        // ── Phase 2: negotiate capabilities ──────────────────────────
        send_command(&mut writer, "qmp_capabilities").await?;

        let msg = read_line_json::<QmpMessage>(&mut reader).await?;
        match msg {
            QmpMessage::Return { .. } => {
                debug!("QMP capabilities negotiated successfully");
            }
            QmpMessage::Error { error } => {
                return Err(QemuError::QmpNegotiate {
                    reason: format!("{}: {}", error.class, error.desc),
                });
            }
            QmpMessage::Event(event) => {
                // Events during negotiation are unexpected but not
                // impossible (e.g. a race with early device init).
                warn!("unexpected QMP event during negotiation: {event}");
                return Err(QemuError::QmpNegotiate {
                    reason: format!("unexpected event during negotiation: {event}"),
                });
            }
        }

        Ok(Self { reader, writer })
    }

    /// Splits the connection into a writer (for sending commands) and an
    /// event stream (for reading events in a background task).
    ///
    /// The writer goes into the [`QemuController`](super::QemuController)
    /// and the event stream goes into the background event-watcher task
    /// spawned during [`launch`](super::Qemu::launch).
    pub fn into_split(self) -> (QmpWriter, QmpEventStream) {
        (
            QmpWriter {
                writer: self.writer,
            },
            QmpEventStream {
                reader: self.reader,
            },
        )
    }
}

// ── QmpWriter ────────────────────────────────────────────────────────

/// Write half of a QMP connection, used for sending lifecycle commands.
///
/// Commands are sent fire-and-forget: the response (if any) will be
/// consumed and discarded by the [`QmpEventStream`] on the read half,
/// or simply lost if QEMU has already exited.
///
/// This design is appropriate because:
///
/// - **During normal operation**, the event stream task owns the read
///   half and will discard any command responses it encounters.
/// - **During shutdown** (which runs after the event stream task
///   completes), the VM has usually already exited, so writes may fail
///   with a broken pipe.  The best-effort semantics mean these failures
///   are harmless.
pub struct QmpWriter {
    writer: OwnedWriteHalf,
}

impl QmpWriter {
    /// Sends a QMP command without waiting for a response.
    ///
    /// This is suitable for best-effort operations like shutdown where
    /// the caller does not need to know whether the command succeeded.
    /// Errors are logged at debug level but not propagated.
    pub async fn send_command_fire_and_forget(&mut self, command: &str) {
        if let Err(err) = send_command(&mut self.writer, command).await {
            debug!("QMP command `{command}` send failed (best-effort): {err}");
        }
    }
}

// ── QmpEventStream ───────────────────────────────────────────────────

/// Read half of a QMP connection, used for consuming events in a
/// background task.
///
/// Reads newline-delimited JSON messages from the QMP socket and yields
/// [`QmpEvent`]s.  Command responses (`Return` / `Error`) that arrive
/// on the stream are logged and discarded, since the writer sends
/// commands fire-and-forget.
pub(crate) struct QmpEventStream {
    reader: BufReader<OwnedReadHalf>,
}

impl QmpEventStream {
    /// Reads the next QMP event from the stream.
    ///
    /// Skips over command responses (which may arrive if the writer sent
    /// a fire-and-forget command while the event stream was active).
    ///
    /// Returns `Ok(None)` when the stream is closed (QEMU exited and
    /// the socket was shut down).
    ///
    /// # Errors
    ///
    /// Returns [`QemuError`] on I/O or deserialization errors.
    pub async fn next_event(&mut self) -> Result<Option<QmpEvent>, QemuError> {
        loop {
            let mut line = String::new();
            let bytes_read = self
                .reader
                .read_line(&mut line)
                .await
                .map_err(QemuError::QmpIo)?;

            if bytes_read == 0 {
                // EOF -- QEMU exited and the socket was closed.
                return Ok(None);
            }

            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            trace!("QMP recv: {trimmed}");

            let msg: QmpMessage =
                serde_json::from_str(trimmed).map_err(QemuError::QmpDeserialize)?;

            match msg {
                QmpMessage::Event(event) => return Ok(Some(event)),
                QmpMessage::Return { .. } => {
                    // Discard command responses -- the writer doesn't wait
                    // for them.
                    trace!("QMP: discarding command success response");
                }
                QmpMessage::Error { error } => {
                    // Log command errors but don't propagate -- the writer
                    // sent fire-and-forget.
                    debug!(
                        "QMP: discarding command error response: {}: {}",
                        error.class, error.desc
                    );
                }
            }
        }
    }
}

// ── Internal helpers ─────────────────────────────────────────────────

/// Reads a single newline-delimited JSON message from the buffered
/// reader and deserializes it into `T`.
async fn read_line_json<T: serde::de::DeserializeOwned>(
    reader: &mut BufReader<OwnedReadHalf>,
) -> Result<T, QemuError> {
    let mut line = String::new();
    let bytes_read = reader.read_line(&mut line).await.map_err(QemuError::QmpIo)?;
    if bytes_read == 0 {
        return Err(QemuError::QmpGreeting {
            reason: "connection closed before message received".into(),
        });
    }
    let trimmed = line.trim();
    trace!("QMP recv: {trimmed}");
    serde_json::from_str(trimmed).map_err(QemuError::QmpDeserialize)
}

/// Serializes and sends a QMP command as a newline-terminated JSON
/// message.
async fn send_command(writer: &mut OwnedWriteHalf, command: &str) -> Result<(), QemuError> {
    let cmd = QmpCommand { execute: command };
    let mut payload = serde_json::to_string(&cmd).map_err(|e| QemuError::QmpCommand {
        command: command.to_owned(),
        reason: format!("serialization failed: {e}"),
    })?;
    payload.push('\n');
    trace!("QMP send: {}", payload.trim());
    writer
        .write_all(payload.as_bytes())
        .await
        .map_err(QemuError::QmpIo)?;
    writer.flush().await.map_err(QemuError::QmpIo)?;
    Ok(())
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_greeting() {
        let json = r#"{"QMP": {"version": {"qemu": {"micro": 0, "minor": 2, "major": 9}, "package": "v9.2.0"}, "capabilities": ["oob"]}}"#;
        let greeting: QmpGreeting = serde_json::from_str(json).unwrap();
        assert_eq!(greeting.qmp.version.qemu.major, 9);
        assert_eq!(greeting.qmp.version.qemu.minor, 2);
        assert_eq!(greeting.qmp.version.qemu.micro, 0);
        assert_eq!(greeting.qmp.capabilities, vec!["oob"]);
    }

    #[test]
    fn deserialize_greeting_without_capabilities() {
        let json = r#"{"QMP": {"version": {"qemu": {"micro": 1, "minor": 0, "major": 8}, "package": ""}}}"#;
        let greeting: QmpGreeting = serde_json::from_str(json).unwrap();
        assert_eq!(greeting.qmp.version.qemu.major, 8);
        assert!(greeting.qmp.capabilities.is_empty());
    }

    #[test]
    fn deserialize_return_response() {
        let json = r#"{"return": {}}"#;
        let msg: QmpMessage = serde_json::from_str(json).unwrap();
        assert!(matches!(msg, QmpMessage::Return { .. }));
    }

    #[test]
    fn deserialize_return_with_data() {
        let json = r#"{"return": {"status": "running", "singlestep": false}}"#;
        let msg: QmpMessage = serde_json::from_str(json).unwrap();
        assert!(matches!(msg, QmpMessage::Return { .. }));
    }

    #[test]
    fn deserialize_error_response() {
        let json =
            r#"{"error": {"class": "GenericError", "desc": "something went wrong"}}"#;
        let msg: QmpMessage = serde_json::from_str(json).unwrap();
        match msg {
            QmpMessage::Error { error } => {
                assert_eq!(error.class, "GenericError");
                assert_eq!(error.desc, "something went wrong");
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn deserialize_shutdown_event() {
        let json = r#"{"event": "SHUTDOWN", "data": {"guest": true, "reason": "guest-shutdown"}, "timestamp": {"seconds": 1234, "microseconds": 5678}}"#;
        let msg: QmpMessage = serde_json::from_str(json).unwrap();
        match msg {
            QmpMessage::Event(event) => {
                assert_eq!(event.event, "SHUTDOWN");
                assert_eq!(event.data["guest"], true);
                assert_eq!(event.data["reason"], "guest-shutdown");
            }
            other => panic!("expected Event, got {other:?}"),
        }
    }

    #[test]
    fn deserialize_guest_panicked_event() {
        let json = r#"{"event": "GUEST_PANICKED", "data": {"action": "pause"}, "timestamp": {"seconds": 42, "microseconds": 0}}"#;
        let msg: QmpMessage = serde_json::from_str(json).unwrap();
        match msg {
            QmpMessage::Event(event) => {
                assert_eq!(event.event, "GUEST_PANICKED");
                assert_eq!(event.data["action"], "pause");
            }
            other => panic!("expected Event, got {other:?}"),
        }
    }

    #[test]
    fn deserialize_event_without_data() {
        let json = r#"{"event": "STOP", "timestamp": {"seconds": 10, "microseconds": 0}}"#;
        let msg: QmpMessage = serde_json::from_str(json).unwrap();
        match msg {
            QmpMessage::Event(event) => {
                assert_eq!(event.event, "STOP");
                assert!(event.data.is_null());
            }
            other => panic!("expected Event, got {other:?}"),
        }
    }

    #[test]
    fn event_display_with_data() {
        let event = QmpEvent {
            event: "SHUTDOWN".into(),
            data: serde_json::json!({"guest": true}),
            timestamp: serde_json::Value::Null,
        };
        assert_eq!(format!("{event}"), r#"SHUTDOWN {"guest":true}"#);
    }

    #[test]
    fn event_display_without_data() {
        let event = QmpEvent {
            event: "STOP".into(),
            data: serde_json::Value::Null,
            timestamp: serde_json::Value::Null,
        };
        assert_eq!(format!("{event}"), "STOP");
    }

    #[test]
    fn messages_deserialize_unambiguously() {
        // Verify that each message type deserializes to the correct
        // variant and does not accidentally match another variant.
        let return_json = r#"{"return": {"id": 1}}"#;
        let error_json = r#"{"error": {"class": "X", "desc": "Y"}}"#;
        let event_json = r#"{"event": "RESET", "timestamp": {"seconds": 0, "microseconds": 0}}"#;

        assert!(matches!(
            serde_json::from_str::<QmpMessage>(return_json).unwrap(),
            QmpMessage::Return { .. }
        ));
        assert!(matches!(
            serde_json::from_str::<QmpMessage>(error_json).unwrap(),
            QmpMessage::Error { .. }
        ));
        assert!(matches!(
            serde_json::from_str::<QmpMessage>(event_json).unwrap(),
            QmpMessage::Event(_)
        ));
    }
}