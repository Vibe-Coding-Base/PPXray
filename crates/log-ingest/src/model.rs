//! Event model produced by the parser and persisted in DuckDB.

use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/ipc-schema/src/generated/")]
pub enum Proto {
    Tcp,
    Udp,
    Icmp,
}

impl Proto {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
            Self::Icmp => "ICMP",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/ipc-schema/src/generated/")]
pub enum Action {
    Direct,
    Proxy,
    Block,
    /// Used for session events (open/close/error) that don't carry an action.
    Other,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "Direct",
            Self::Proxy => "Proxy",
            Self::Block => "Block",
            Self::Other => "Other",
        }
    }

    pub fn parse(s: &str) -> Self {
        // Real-world log phrasings (the tail after `rule : `):
        //   "direct connection"
        //   "connection blocked"
        //   "proxy <name> SOCKS5 127.0.0.1:1080"
        //   "close, ..." / "error: ..." etc.
        // We probe by keyword so phrasing order doesn't matter. Order of
        // checks: block > proxy > direct — blocking is the strongest signal
        // and shouldn't be masked by coincidental substrings.
        let lower = s.to_ascii_lowercase();
        if lower.contains("block") {
            Self::Block
        } else if lower.contains("proxy") {
            Self::Proxy
        } else if lower.contains("direct") {
            Self::Direct
        } else {
            Self::Other
        }
    }
}

/// Primary connection-matching event. The log line that says
/// `... matching <rule> rule : <action>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionEvent {
    pub ts: NaiveDateTime,
    pub process: String,
    pub pid: Option<u32>,
    pub parent: Option<String>,
    pub proto: Proto,
    pub ipv6: bool,
    /// Hostname if present (e.g. `teams.events.data.microsoft.com`), else `None`.
    pub dst_host: Option<String>,
    /// Canonical IP string (may be None when Proxifier couldn't resolve).
    pub dst_ip: Option<String>,
    pub dst_port: u16,
    pub matched_rule: Option<String>,
    pub action: Action,
    /// Byte offset of this line's `[` in the source file — for "jump to raw
    /// line" navigation in the UI.
    pub raw_offset: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsEvent {
    pub ts: NaiveDateTime,
    pub process: String,
    pub pid: Option<u32>,
    pub qname: String,
    pub qtype: Option<u16>,
    pub server: Option<String>,
    pub answer_ip: Option<String>,
    pub ttl: Option<u32>,
    pub kind: DnsKind,
    pub raw_offset: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsKind {
    Request,
    Response,
    EmptyResponse,
    /// `<name> resolve via <server>:<port> : DNS` — informational.
    Resolve,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Connection(ConnectionEvent),
    Dns(DnsEvent),
    /// Any line the parser recognized but didn't classify — e.g. session
    /// bytes-transferred footer. Stored so the raw log viewer isn't lossy.
    Other {
        ts: Option<NaiveDateTime>,
        raw_offset: u64,
        len: u32,
    },
}
