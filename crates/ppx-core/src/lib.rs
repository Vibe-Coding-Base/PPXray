//! Parse and serialize Proxifier `.ppx` profile files.
//!
//! Goals:
//! - **Lossless round-trip** of every field found in real profiles (see fixtures).
//! - Fail fast on structural surprises rather than silently dropping data.
//! - Produce clean XML that Proxifier accepts.

mod error;
pub mod exposure;
pub mod matcher;
mod model;
mod parser;
mod serializer;
pub mod validate;

pub use error::{PpxError, PpxResult};
pub use exposure::{
    ExitChannel, ExitChannelKind, ExposureFinding, ExposureGraph, ExposureSummary, FindingCounts,
    FindingKind, FindingSeverity, Flow, ProcessBucket, ProcessBucketKind, RuleActionKind, RuleRef,
    breadth_score, compute_exposure,
};
pub use matcher::{
    Candidate, FieldOutcome, RuleEvaluation, ShadowField, ShadowPair, ShadowReason,
    SimulationResult, WinnerAction, overshadow_pairs, simulate,
};
pub use model::{
    Authentication, Chain, ChainMember, ConnectionLoopDetection, Encryption, ExclusionList,
    Options, Profile, Proxy, ProxyType, Resolve, Rule, RuleAction,
};
pub use validate::{EntryKind, classify_target, validate_application, validate_port};

/// Parse a `.ppx` profile from an XML string.
pub fn parse_str(xml: &str) -> PpxResult<Profile> {
    parser::parse(xml)
}

/// Serialize a `Profile` to a `.ppx`-compatible XML string.
pub fn to_xml_string(profile: &Profile) -> PpxResult<String> {
    serializer::serialize(profile)
}
