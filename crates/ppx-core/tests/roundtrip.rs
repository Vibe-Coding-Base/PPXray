//! End-to-end tests against a full-size `.ppx` profile fixture.
//!
//! The critical invariant we enforce is **semantic round-trip**: taking a
//! parsed profile, serializing it, and parsing the result must yield an
//! identical in-memory model. This was the root cause of data loss in the
//! previous (Electron / xml2js) implementation.

use pretty_assertions::assert_eq;

use ppx_core::{Profile, ProxyType, RuleAction, parse_str, to_xml_string};

const SAMPLE_PROFILE: &str = include_str!("fixtures/sample_profile.ppx");

#[test]
fn parses_sample_profile() {
    let profile = parse_str(SAMPLE_PROFILE).expect("sample profile should parse");

    // Sanity: header.
    assert_eq!(profile.version, 102);
    assert_eq!(profile.platform, "Windows");

    // Sanity: Options tree.
    assert!(profile.options.resolve.auto_mode_detection);
    assert_eq!(profile.options.udp_mode, "mode_block_all");
    assert!(profile.options.process_other_users);
    assert!(profile.options.encryption.is_some());
    assert_eq!(profile.options.encryption.as_ref().unwrap().mode, "master");
    assert!(profile.options.encryption.as_ref().unwrap().hash.is_some());

    // Sanity: proxies.
    assert_eq!(profile.proxies.len(), 3);
    assert_eq!(profile.proxies[0].id, 101);
    assert!(matches!(profile.proxies[0].proxy_type, ProxyType::Socks5));
    assert_eq!(profile.proxies[0].options, Some(48));
    assert_eq!(profile.proxies[2].label.as_deref(), Some("Home Tor"));

    // Sanity: chains.
    assert!(profile.chains.is_empty());

    // Sanity: rules — count and critical field preservation.
    assert!(
        profile.rules.len() > 100,
        "sample profile has many rules, got {}",
        profile.rules.len()
    );

    let localhost = profile.rules.iter().find(|r| r.name == "Localhost 1").unwrap();
    assert!(matches!(localhost.action, RuleAction::Direct));
    assert!(localhost.targets.contains(&"localhost".to_string()));
    assert!(localhost.targets.contains(&"127.0.0.1".to_string()));

    // A CIDR target survives the round trip as written, rather than being
    // normalised into a range or an address.
    let cidr = profile.rules.iter().find(|r| r.name == "Mail 4").unwrap();
    assert!(cidr.targets.contains(&"203.0.113.0/24".to_string()));

    // A hostname-and-wildcard target list keeps both forms distinct.
    let hosts = profile.rules.iter().find(|r| r.name.starts_with("Telemetry & analytics")).unwrap();
    assert!(hosts.targets.contains(&"api.example".to_string()));
    assert!(hosts.targets.contains(&"*.api.example".to_string()));

    // The last rule is the catch-all, and its action must survive as Block -
    // reading it as Direct would invert the profile's meaning.
    let last = profile.rules.last().unwrap();
    assert_eq!(last.name, "Chat 155");
    assert!(matches!(last.action, RuleAction::Block));
    assert!(last.targets.is_empty());
    assert!(last.applications.is_empty());
    assert!(last.ports.is_empty());

    // Ampersand-bearing rule name must survive XML unescaping.
    let eset = profile
        .rules
        .iter()
        .find(|r| r.name.contains("Telemetry & analytics"))
        .expect("ampersand-bearing rule should parse intact");
    assert!(!eset.enabled);
}

#[test]
fn semantic_round_trip() {
    let first: Profile = parse_str(SAMPLE_PROFILE).expect("parse 1");
    let xml = to_xml_string(&first).expect("serialize");
    let second: Profile = parse_str(&xml).expect("parse 2");
    assert_eq!(first, second, "semantic round-trip must be lossless");
}

#[test]
fn serialized_output_is_stable() {
    // Snapshot the first ~2 KB so reviewers can sanity-check formatting
    // changes without pasting a 40 KB document into the diff.
    let profile: Profile = parse_str(SAMPLE_PROFILE).expect("parse");
    let xml = to_xml_string(&profile).expect("serialize");
    let head: String = xml.chars().take(2048).collect();
    insta::assert_snapshot!("sample_profile_head_2k", head);
}

#[test]
fn ampersand_escape_round_trip() {
    let xml = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<ProxifierProfile version="102" platform="Windows" product_id="0" product_minver="400">
    <Options>
        <Resolve>
            <AutoModeDetection enabled="true" />
            <ViaProxy enabled="false" />
            <BlockNonATypes enabled="true" />
            <ExclusionList OnlyFromListMode="false">localhost</ExclusionList>
            <DnsUdpMode>0</DnsUdpMode>
        </Resolve>
        <ConnectionLoopDetection enabled="false" resolve="false" />
        <Udp mode="mode_block_all" />
        <LeakPreventionMode enabled="false" />
        <ProcessOtherUsers enabled="true" />
        <ProcessServices enabled="true" />
        <HandleDirectConnections enabled="false" />
        <HttpProxiesSupport enabled="false" />
    </Options>
    <ProxyList />
    <ChainList />
    <RuleList>
        <Rule enabled="true">
            <Action type="Direct" />
            <Targets>foo.com</Targets>
            <Name>A &amp; B &lt;test&gt;</Name>
        </Rule>
    </RuleList>
</ProxifierProfile>
"#;
    let first = parse_str(xml).unwrap();
    assert_eq!(first.rules[0].name, "A & B <test>");
    let written = to_xml_string(&first).unwrap();
    assert!(written.contains("A &amp; B &lt;test&gt;"), "XML output: {written}");
    let second = parse_str(&written).unwrap();
    assert_eq!(first, second);
}

#[test]
fn ports_preserved() {
    let profile: Profile = parse_str(SAMPLE_PROFILE).expect("parse");
    // Several rules with multi-port strings should split cleanly.
    let single = profile.rules.iter().find(|r| r.name == "Catch-all 15").unwrap();
    assert_eq!(single.ports, vec!["123".to_string()]);

    // Written as "443; 80" - the separator and the space both have to go.
    let two = profile.rules.iter().find(|r| r.name == "Internal range 13").unwrap();
    assert_eq!(two.ports, vec!["443".to_string(), "80".to_string()]);

    // Written as "443; 5223".
    let high = profile.rules.iter().find(|r| r.name == "Localhost 91").unwrap();
    assert_eq!(high.ports, vec!["443".to_string(), "5223".to_string()]);
}

#[test]
fn applications_preserved() {
    let profile: Profile = parse_str(SAMPLE_PROFILE).expect("parse");
    // Applications-only rule (no Targets).
    let apps_only = profile.rules.iter().find(|r| r.name == "Updates 9").unwrap();
    assert!(apps_only.targets.is_empty());
    assert_eq!(apps_only.applications.len(), 1);
    assert!(apps_only.applications[0].contains("updater.exe"));
}
