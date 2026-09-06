//! Strongly-typed Proxifier profile model.
//!
//! Field coverage is exhaustive for the structures observed in real `.ppx`
//! files shipped with Proxifier (Windows profile version 102). Unknown
//! elements cause a parse error rather than silent data loss.

use serde::{Deserialize, Serialize};
use ts_rs::TS;

// ----------------------------------------------------------------------------
// Top-level
// ----------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/ipc-schema/src/generated/")]
pub struct Profile {
    pub version: u32,
    pub platform: String,
    /// `product_id` attribute, usually `"0"`. Kept as string to not lose leading zeroes.
    pub product_id: String,
    /// `product_minver` attribute, usually `"400"`.
    pub product_minver: String,
    pub options: Options,
    pub proxies: Vec<Proxy>,
    pub chains: Vec<Chain>,
    pub rules: Vec<Rule>,
}

impl Profile {
    pub fn empty() -> Self {
        Self {
            version: 102,
            platform: "Windows".into(),
            product_id: "0".into(),
            product_minver: "400".into(),
            options: Options::default(),
            proxies: vec![],
            chains: vec![],
            rules: vec![],
        }
    }
}

// ----------------------------------------------------------------------------
// Options
// ----------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS, Default)]
#[ts(export, export_to = "../../../packages/ipc-schema/src/generated/")]
pub struct Options {
    pub resolve: Resolve,
    pub encryption: Option<Encryption>,
    pub connection_loop_detection: ConnectionLoopDetection,
    /// Raw UDP mode string, e.g. `"mode_block_all"`, `"mode_tunnel_all"`.
    pub udp_mode: String,
    pub leak_prevention_mode: bool,
    pub process_other_users: bool,
    pub process_services: bool,
    pub handle_direct_connections: bool,
    pub http_proxies_support: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/ipc-schema/src/generated/")]
pub struct Resolve {
    pub auto_mode_detection: bool,
    pub via_proxy: bool,
    pub block_non_a_types: bool,
    pub exclusion_list: ExclusionList,
    pub dns_udp_mode: u32,
}

impl Default for Resolve {
    fn default() -> Self {
        Self {
            auto_mode_detection: true,
            via_proxy: false,
            block_non_a_types: true,
            exclusion_list: ExclusionList::default(),
            dns_udp_mode: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/ipc-schema/src/generated/")]
pub struct ExclusionList {
    pub only_from_list_mode: bool,
    pub value: String,
}

impl Default for ExclusionList {
    fn default() -> Self {
        Self { only_from_list_mode: false, value: "%ComputerName%; localhost; *.local".into() }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/ipc-schema/src/generated/")]
pub struct Encryption {
    /// E.g. `"master"`.
    pub mode: String,
    /// Base64-encoded encryption hash.
    pub hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS, Default)]
#[ts(export, export_to = "../../../packages/ipc-schema/src/generated/")]
pub struct ConnectionLoopDetection {
    pub enabled: bool,
    pub resolve: bool,
}

// ----------------------------------------------------------------------------
// Proxy
// ----------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/ipc-schema/src/generated/")]
pub enum ProxyType {
    #[serde(rename = "SOCKS4")]
    Socks4,
    #[serde(rename = "SOCKS5")]
    Socks5,
    #[serde(rename = "HTTPS")]
    Https,
    #[serde(rename = "HTTP")]
    Http,
}

impl ProxyType {
    pub fn as_xml_str(self) -> &'static str {
        match self {
            Self::Socks4 => "SOCKS4",
            Self::Socks5 => "SOCKS5",
            Self::Https => "HTTPS",
            Self::Http => "HTTP",
        }
    }

    pub fn from_xml_str(s: &str) -> Option<Self> {
        match s {
            "SOCKS4" => Some(Self::Socks4),
            "SOCKS5" => Some(Self::Socks5),
            "HTTPS" => Some(Self::Https),
            "HTTP" => Some(Self::Http),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/ipc-schema/src/generated/")]
pub struct Proxy {
    pub id: u32,
    pub proxy_type: ProxyType,
    pub address: String,
    pub port: u16,
    /// Proxifier's proxy options bitfield. 48 = auth + encrypt.
    pub options: Option<u32>,
    pub label: Option<String>,
    pub authentication: Option<Authentication>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/ipc-schema/src/generated/")]
pub struct Authentication {
    pub username: Option<String>,
    /// Encoded (base64) password as stored in the profile. Never plaintext.
    pub password: Option<String>,
}

// ----------------------------------------------------------------------------
// Chain
// ----------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/ipc-schema/src/generated/")]
pub struct Chain {
    pub id: u32,
    pub name: Option<String>,
    pub members: Vec<ChainMember>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/ipc-schema/src/generated/")]
pub struct ChainMember {
    pub proxy_id: u32,
}

// ----------------------------------------------------------------------------
// Rule
// ----------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/ipc-schema/src/generated/")]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum RuleAction {
    Direct,
    Block,
    Proxy { proxy_id: u32 },
    Chain { chain_id: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/ipc-schema/src/generated/")]
pub struct Rule {
    pub enabled: bool,
    pub name: String,
    pub action: RuleAction,
    /// Target hosts / IPs / CIDRs / wildcards. Empty = match any.
    pub targets: Vec<String>,
    /// Process paths or globs. Empty = match any.
    pub applications: Vec<String>,
    /// Ports or port ranges as strings (e.g. `"443"`, `"8000-8100"`).
    pub ports: Vec<String>,
}

impl Rule {
    pub fn new_default() -> Self {
        Self {
            enabled: true,
            name: "New Rule".into(),
            action: RuleAction::Direct,
            targets: vec![],
            applications: vec![],
            ports: vec![],
        }
    }
}
