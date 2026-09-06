//! The HTTP path, exercised end to end against a stub server.
//!
//! Everything else in this crate is unit-tested on pure functions, which
//! leaves the part that actually matters untested: that a request built by
//! `build_body` reaches a socket with the right method, path and headers,
//! that a real response parses, and that the audit log records what happened.
//! Until this file existed the whole feature had never made a request at all.
//!
//! The stub speaks just enough HTTP/1.1 to serve one request per connection.
//! That is deliberate — a mock library would be a dependency, and the point
//! here is to test our bytes, not someone else's framework.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;

use llm_bridge::audit::{AuditLog, AuditOutcome, digest};
use llm_bridge::config::{LlmSettings, ProviderKind};
use llm_bridge::provider::{ChatRequest, Turn};
use llm_bridge::{LlmClient, LlmError};

/// What the stub saw.
#[derive(Debug, Clone)]
struct Captured {
    request_line: String,
    headers: Vec<(String, String)>,
    body: String,
}

impl Captured {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

/// A one-shot HTTP server. Returns its base URL and a channel carrying the
/// request it received.
fn stub(status: u16, response_body: &'static str) -> (String, mpsc::Receiver<Captured>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let Ok((stream, _)) = listener.accept() else { return };
        if let Some(captured) = serve(stream, status, response_body) {
            let _ = tx.send(captured);
        }
    });

    (format!("http://127.0.0.1:{port}"), rx)
}

fn serve(mut stream: TcpStream, status: u16, body: &str) -> Option<Captured> {
    let mut reader = BufReader::new(stream.try_clone().ok()?);

    let mut request_line = String::new();
    reader.read_line(&mut request_line).ok()?;

    let mut headers = Vec::new();
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).ok()? == 0 {
            break;
        }
        let line = line.trim_end().to_string();
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            let (k, v) = (k.trim().to_string(), v.trim().to_string());
            if k.eq_ignore_ascii_case("content-length") {
                content_length = v.parse().unwrap_or(0);
            }
            headers.push((k, v));
        }
    }

    let mut buf = vec![0u8; content_length];
    reader.read_exact(&mut buf).ok()?;

    let reason = if status == 200 { "OK" } else { "Error" };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).ok()?;
    stream.flush().ok()?;

    Some(Captured {
        request_line: request_line.trim_end().to_string(),
        headers,
        body: String::from_utf8_lossy(&buf).into_owned(),
    })
}

fn settings(provider: ProviderKind, base_url: &str) -> LlmSettings {
    LlmSettings {
        enabled: true,
        provider,
        base_url: base_url.to_string(),
        model: match provider {
            ProviderKind::Anthropic => "claude-opus-5".into(),
            ProviderKind::OpenAiCompatible => "llama3.1".into(),
        },
        reviewed_payload: true,
        ..Default::default()
    }
}

fn request() -> ChatRequest {
    ChatRequest {
        system: "schema goes here".into(),
        turns: vec![Turn::User("which process is noisiest?".into())],
        tools: vec![llm_bridge::prompt::sql_tool()],
    }
}

fn client() -> (tempfile::TempDir, AuditLog, LlmClient) {
    let dir = tempfile::tempdir().unwrap();
    let log = AuditLog::new(dir.path().join("audit.jsonl"));
    let client = LlmClient::new(log.clone()).unwrap();
    (dir, log, client)
}

const ANTHROPIC_OK: &str = r#"{
  "content": [
    {"type": "thinking", "thinking": "counting per process"},
    {"type": "text", "text": "Here is what I found."},
    {"type": "tool_use", "id": "toolu_1", "name": "run_sql",
     "input": {"sql": "SELECT process FROM events", "purpose": "rank"}}
  ],
  "stop_reason": "tool_use",
  "usage": {"input_tokens": 120, "output_tokens": 34, "cache_read_input_tokens": 100}
}"#;

const OPENAI_OK: &str = r#"{
  "choices": [{
    "message": {"content": "found it", "tool_calls": [
      {"id": "call_9", "type": "function",
       "function": {"name": "run_sql", "arguments": "{\"sql\":\"SELECT 1\",\"purpose\":\"p\"}"}}
    ]},
    "finish_reason": "tool_calls"
  }],
  "usage": {"prompt_tokens": 7, "completion_tokens": 11}
}"#;

#[tokio::test]
async fn anthropic_request_reaches_the_wire_in_the_documented_shape() {
    let (base, rx) = stub(200, ANTHROPIC_OK);
    let (_dir, log, client) = client();
    let cfg = settings(ProviderKind::Anthropic, &base);

    let completion =
        client.send(&cfg, Some("sk-ant-test"), "chat", &request()).await.expect("send");

    let got = rx.recv().expect("stub saw a request");
    assert_eq!(got.request_line, "POST /v1/messages HTTP/1.1");
    assert_eq!(got.header("x-api-key"), Some("sk-ant-test"));
    assert_eq!(got.header("anthropic-version"), Some("2023-06-01"));
    assert_eq!(got.header("content-type"), Some("application/json"));

    let sent: serde_json::Value = serde_json::from_str(&got.body).expect("body is JSON");
    assert_eq!(sent["model"], "claude-opus-5");
    assert_eq!(sent["thinking"]["type"], "adaptive");
    assert_eq!(sent["system"][0]["cache_control"]["type"], "ephemeral");
    assert_eq!(sent["tools"][0]["name"], "run_sql");
    assert_eq!(sent["messages"][0]["content"], "which process is noisiest?");

    assert_eq!(completion.text, "Here is what I found.");
    assert_eq!(completion.thinking, "counting per process");
    assert_eq!(completion.calls[0].input["sql"], "SELECT process FROM events");
    assert_eq!(completion.usage.cache_read_tokens, Some(100));

    // The audit line must describe the request that actually went, digest
    // included - that is what makes the preview checkable after the fact.
    let entries = log.recent(10).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].outcome, AuditOutcome::Ok);
    assert_eq!(entries[0].request_sha256, digest(got.body.as_bytes()));
    assert_eq!(entries[0].request_bytes, got.body.len() as u64);
    assert_eq!(entries[0].input_tokens, Some(120));
    // Scheme and authority only; no path, and above all no key.
    assert_eq!(entries[0].endpoint, base);
    assert!(!entries[0].endpoint.contains("sk-ant"));
}

#[tokio::test]
async fn openai_compatible_request_uses_the_other_dialect() {
    let (base, rx) = stub(200, OPENAI_OK);
    let (_dir, _log, client) = client();
    let cfg = settings(ProviderKind::OpenAiCompatible, &format!("{base}/v1"));

    let completion = client.send(&cfg, Some("sk-local"), "chat", &request()).await.expect("send");

    let got = rx.recv().expect("stub saw a request");
    assert_eq!(got.request_line, "POST /v1/chat/completions HTTP/1.1");
    assert_eq!(got.header("authorization"), Some("Bearer sk-local"));
    assert!(got.header("x-api-key").is_none(), "the Anthropic header must not leak here");

    let sent: serde_json::Value = serde_json::from_str(&got.body).unwrap();
    assert_eq!(sent["messages"][0]["role"], "system");
    assert_eq!(sent["tools"][0]["type"], "function");
    assert!(sent.get("thinking").is_none(), "no thinking key in this dialect");

    assert_eq!(completion.text, "found it");
    assert_eq!(completion.calls[0].input["sql"], "SELECT 1");
}

#[tokio::test]
async fn a_local_endpoint_with_no_key_sends_no_credential_header() {
    let (base, rx) = stub(200, OPENAI_OK);
    let (_dir, _log, client) = client();
    let cfg = settings(ProviderKind::OpenAiCompatible, &format!("{base}/v1"));

    client.send(&cfg, None, "chat", &request()).await.expect("send");

    let got = rx.recv().unwrap();
    assert!(got.header("authorization").is_none(), "Ollama needs no credential");
}

#[tokio::test]
async fn a_provider_error_surfaces_its_body_and_is_audited_as_failed() {
    let (base, _rx) = stub(401, r#"{"error":{"message":"invalid x-api-key"}}"#);
    let (_dir, log, client) = client();
    let cfg = settings(ProviderKind::Anthropic, &base);

    let err = client.send(&cfg, Some("bad"), "chat", &request()).await.unwrap_err();
    match err {
        LlmError::Status { status, ref body, .. } => {
            assert_eq!(status, 401);
            // The provider's own message is the only useful diagnostic for a
            // wrong key or a bad model name, so it has to reach the user.
            assert!(body.contains("invalid x-api-key"));
        }
        other => panic!("expected a status error, got {other:?}"),
    }
    assert!(!err.is_retryable(), "a 401 will fail identically forever");

    let entries = log.recent(10).unwrap();
    assert_eq!(entries[0].outcome, AuditOutcome::Failed);
    assert!(entries[0].detail.as_deref().unwrap().contains("401"));
}

#[tokio::test]
async fn a_rate_limit_is_reported_as_retryable() {
    let (base, _rx) = stub(429, r#"{"error":{"message":"slow down"}}"#);
    let (_dir, _log, client) = client();
    let cfg = settings(ProviderKind::Anthropic, &base);

    let err = client.send(&cfg, Some("k"), "chat", &request()).await.unwrap_err();
    assert!(err.is_retryable());
}

#[tokio::test]
async fn a_non_json_body_is_a_protocol_error_not_a_panic() {
    // A captive portal or a proxy error page is the realistic case here, and
    // this app is routinely run behind a proxy.
    let (base, _rx) = stub(200, "<html><body>Blocked by policy</body></html>");
    let (_dir, _log, client) = client();
    let cfg = settings(ProviderKind::Anthropic, &base);

    let err = client.send(&cfg, Some("k"), "chat", &request()).await.unwrap_err();
    assert!(matches!(err, LlmError::Protocol(_)), "got {err:?}");
}

#[tokio::test]
async fn a_refusal_is_reported_as_a_refusal_and_still_counts_as_a_completed_send() {
    let (base, _rx) = stub(
        200,
        r#"{"content": [], "stop_reason": "refusal",
            "stop_details": {"type": "refusal", "category": "cyber", "explanation": "declined"}}"#,
    );
    let (_dir, log, client) = client();
    let cfg = settings(ProviderKind::Anthropic, &base);

    let err = client.send(&cfg, Some("k"), "chat", &request()).await.unwrap_err();
    match err {
        LlmError::Refused(ref why) => assert_eq!(why, "declined"),
        other => panic!("expected a refusal, got {other:?}"),
    }

    // It reached the provider and the provider answered, so the egress log
    // records a completed request rather than a failure.
    let entries = log.recent(10).unwrap();
    assert_eq!(entries[0].outcome, AuditOutcome::Ok);
}

#[tokio::test]
async fn a_disabled_assistant_never_opens_a_socket() {
    let (base, rx) = stub(200, ANTHROPIC_OK);
    let (_dir, log, client) = client();
    let cfg = LlmSettings { base_url: base, ..Default::default() }; // enabled: false

    let err = client.send(&cfg, Some("k"), "chat", &request()).await.unwrap_err();
    assert!(matches!(err, LlmError::Disabled));

    // Nothing reached the listener, and nothing was written to the log.
    assert!(rx.recv_timeout(std::time::Duration::from_millis(300)).is_err());
    assert!(log.recent(10).unwrap().is_empty());
}

#[tokio::test]
async fn the_preview_digest_matches_what_the_wire_receives() {
    // The promise the first-send dialog makes: what you read is what is sent.
    // Asserted here against the bytes the server actually got, rather than
    // against another call to the same builder.
    let (base, rx) = stub(200, ANTHROPIC_OK);
    let (_dir, _log, client) = client();
    let cfg = settings(ProviderKind::Anthropic, &base);

    let preview = llm_bridge::preview(&cfg, Some("sk-ant-test"), &request());
    client.send(&cfg, Some("sk-ant-test"), "chat", &request()).await.expect("send");

    let got = rx.recv().unwrap();
    assert_eq!(preview.sha256, digest(got.body.as_bytes()));
    assert_eq!(preview.bytes, got.body.len() as u64);
}
