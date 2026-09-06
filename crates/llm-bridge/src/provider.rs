//! Turning a conversation into an HTTP request, and a response back into a
//! conversation turn.
//!
//! Two dialects are spoken: Anthropic's Messages API and the
//! OpenAI-compatible `/chat/completions` shape that Ollama, llama.cpp, LM
//! Studio, vLLM and OpenRouter all implement. Everything above this module
//! works in [`Turn`]s and knows about neither.
//!
//! [`build_body`] is a pure function, and that is load-bearing: the payload
//! preview the user is shown before the first send is the return value of
//! this same function, serialized. There is no second code path that could
//! send something the preview did not show.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use ts_rs::TS;

use crate::config::{LlmSettings, ProviderKind, supports_adaptive_thinking};
use crate::error::{LlmError, LlmResult};

/// Anthropic's API version header. Pinned rather than tracked: a newer
/// version can change response shapes, and this crate parses them.
const ANTHROPIC_VERSION: &str = "2023-06-01";

/// Non-streaming ceiling. Large enough that an analysis is never truncated
/// mid-sentence, small enough to stay well inside HTTP timeouts.
const MAX_TOKENS: u32 = 16_000;

/// A call the model wants ppxray to make on its behalf.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub input: Value,
}

/// One step of the conversation, in a shape neither dialect owns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Turn {
    User(String),
    Assistant { text: String, calls: Vec<ToolCall> },
    ToolResult { id: String, name: String, content: String, is_error: bool },
}

/// A tool ppxray is willing to run.
#[derive(Debug, Clone)]
pub struct ToolSpec {
    pub name: &'static str,
    pub description: &'static str,
    pub schema: Value,
}

/// Everything needed to build one request.
#[derive(Debug, Clone)]
pub struct ChatRequest {
    pub system: String,
    pub turns: Vec<Turn>,
    pub tools: Vec<ToolSpec>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/ipc-schema/src/generated/")]
pub struct Usage {
    pub input_tokens: Option<u32>,
    pub output_tokens: Option<u32>,
    /// Anthropic only. Watched because the schema and system prompt are the
    /// same on every turn of a conversation, so a zero here across turns
    /// means the cache breakpoint stopped working.
    pub cache_read_tokens: Option<u32>,
}

/// What came back, normalized.
#[derive(Debug, Clone)]
pub struct Completion {
    pub text: String,
    /// Summarized reasoning, when the provider returns any. Shown collapsed
    /// in the UI — for a security question, *why* matters as much as *what*.
    pub thinking: String,
    pub calls: Vec<ToolCall>,
    pub usage: Usage,
    pub stop_reason: Option<String>,
}

impl Completion {
    pub fn wants_tools(&self) -> bool {
        !self.calls.is_empty()
    }
}

/// The URL a request for `settings` will be sent to.
pub fn endpoint_url(settings: &LlmSettings) -> String {
    let base = settings.effective_base_url();
    match settings.provider {
        ProviderKind::Anthropic => format!("{base}/v1/messages"),
        ProviderKind::OpenAiCompatible => format!("{base}/chat/completions"),
    }
}

/// Build the exact JSON body that will be sent.
///
/// Pure, and deliberately so — see the module note about the preview.
pub fn build_body(settings: &LlmSettings, req: &ChatRequest) -> Value {
    match settings.provider {
        ProviderKind::Anthropic => anthropic_body(settings, req),
        ProviderKind::OpenAiCompatible => openai_body(settings, req),
    }
}

fn anthropic_body(settings: &LlmSettings, req: &ChatRequest) -> Value {
    let model = settings.effective_model();

    let mut messages = Vec::new();
    for turn in &req.turns {
        match turn {
            Turn::User(text) => messages.push(json!({ "role": "user", "content": text })),
            Turn::Assistant { text, calls } => {
                let mut blocks = Vec::new();
                if !text.is_empty() {
                    blocks.push(json!({ "type": "text", "text": text }));
                }
                for c in calls {
                    blocks.push(json!({
                        "type": "tool_use",
                        "id": c.id,
                        "name": c.name,
                        "input": c.input,
                    }));
                }
                messages.push(json!({ "role": "assistant", "content": blocks }));
            }
            // Tool results are user-role blocks in this dialect. Consecutive
            // ones stay separate messages; the API combines same-role turns.
            Turn::ToolResult { id, content, is_error, .. } => {
                messages.push(json!({
                    "role": "user",
                    "content": [{
                        "type": "tool_result",
                        "tool_use_id": id,
                        "content": content,
                        "is_error": is_error,
                    }],
                }));
            }
        }
    }

    let mut body = json!({
        "model": model,
        "max_tokens": MAX_TOKENS,
        // The system prompt carries the DB schema and does not change
        // between turns of a conversation, so it is the natural cache
        // prefix. Everything volatile (the question, tool results) sits
        // after it in `messages`.
        "system": [{
            "type": "text",
            "text": req.system,
            "cache_control": { "type": "ephemeral" },
        }],
        "messages": messages,
    });

    if supports_adaptive_thinking(model) {
        // `display: summarized` is an explicit opt-in: the default on these
        // models returns thinking blocks with empty text, which would make
        // the reasoning pane permanently blank.
        body["thinking"] = json!({ "type": "adaptive", "display": "summarized" });
    }

    if !req.tools.is_empty() {
        body["tools"] = Value::Array(
            req.tools
                .iter()
                .map(|t| {
                    json!({
                        "name": t.name,
                        "description": t.description,
                        "input_schema": t.schema,
                        // Guarantees the arguments validate against the
                        // schema, so the SQL string is always present and
                        // always a string.
                        "strict": true,
                    })
                })
                .collect(),
        );
    }

    body
}

fn openai_body(settings: &LlmSettings, req: &ChatRequest) -> Value {
    let mut messages = vec![json!({ "role": "system", "content": req.system })];
    for turn in &req.turns {
        match turn {
            Turn::User(text) => messages.push(json!({ "role": "user", "content": text })),
            Turn::Assistant { text, calls } => {
                let mut m = json!({ "role": "assistant", "content": text });
                if !calls.is_empty() {
                    m["tool_calls"] = Value::Array(
                        calls
                            .iter()
                            .map(|c| {
                                json!({
                                    "id": c.id,
                                    "type": "function",
                                    "function": {
                                        "name": c.name,
                                        // This dialect carries arguments as
                                        // a JSON *string*, not an object.
                                        "arguments": c.input.to_string(),
                                    },
                                })
                            })
                            .collect(),
                    );
                }
                messages.push(m);
            }
            Turn::ToolResult { id, content, .. } => messages.push(json!({
                "role": "tool",
                "tool_call_id": id,
                "content": content,
            })),
        }
    }

    let mut body = json!({
        "model": settings.effective_model(),
        "max_tokens": MAX_TOKENS,
        "messages": messages,
    });

    if !req.tools.is_empty() {
        body["tools"] = Value::Array(
            req.tools
                .iter()
                .map(|t| {
                    json!({
                        "type": "function",
                        "function": {
                            "name": t.name,
                            "description": t.description,
                            "parameters": t.schema,
                        },
                    })
                })
                .collect(),
        );
    }

    body
}

/// Parse a 2xx response body into a [`Completion`].
pub fn parse_response(kind: ProviderKind, body: &Value) -> LlmResult<Completion> {
    match kind {
        ProviderKind::Anthropic => parse_anthropic(body),
        ProviderKind::OpenAiCompatible => parse_openai(body),
    }
}

fn parse_anthropic(body: &Value) -> LlmResult<Completion> {
    let blocks = body
        .get("content")
        .and_then(Value::as_array)
        .ok_or_else(|| LlmError::Protocol("response has no `content` array".into()))?;

    let mut text = String::new();
    let mut thinking = String::new();
    let mut calls = Vec::new();

    for b in blocks {
        match b.get("type").and_then(Value::as_str) {
            Some("text") => push_para(&mut text, b.get("text").and_then(Value::as_str)),
            Some("thinking") => push_para(&mut thinking, b.get("thinking").and_then(Value::as_str)),
            Some("tool_use") => calls.push(ToolCall {
                id: b.get("id").and_then(Value::as_str).unwrap_or_default().to_string(),
                name: b.get("name").and_then(Value::as_str).unwrap_or_default().to_string(),
                input: b.get("input").cloned().unwrap_or(Value::Null),
            }),
            _ => {}
        }
    }

    let stop_reason = body.get("stop_reason").and_then(Value::as_str).map(str::to_string);

    // A safety decline arrives as HTTP 200. Reading `content` without
    // checking this would surface an empty answer with no explanation.
    if stop_reason.as_deref() == Some("refusal") {
        let why = body
            .get("stop_details")
            .and_then(|d| d.get("explanation"))
            .and_then(Value::as_str)
            .unwrap_or("the model declined this request");
        return Err(LlmError::Refused(why.to_string()));
    }

    let usage = body.get("usage");
    Ok(Completion {
        text,
        thinking,
        calls,
        usage: Usage {
            input_tokens: usage.and_then(|u| u.get("input_tokens")).and_then(as_u32),
            output_tokens: usage.and_then(|u| u.get("output_tokens")).and_then(as_u32),
            cache_read_tokens: usage
                .and_then(|u| u.get("cache_read_input_tokens"))
                .and_then(as_u32),
        },
        stop_reason,
    })
}

fn parse_openai(body: &Value) -> LlmResult<Completion> {
    let message = body
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|c| c.first())
        .and_then(|c| c.get("message"))
        .ok_or_else(|| LlmError::Protocol("response has no `choices[0].message`".into()))?;

    let text = message.get("content").and_then(Value::as_str).unwrap_or_default().to_string();
    // Several local runtimes expose reasoning models' scratchpad here.
    let thinking =
        message.get("reasoning_content").and_then(Value::as_str).unwrap_or_default().to_string();

    let calls = message
        .get("tool_calls")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .map(|c| {
                    let f = c.get("function");
                    let raw =
                        f.and_then(|f| f.get("arguments")).and_then(Value::as_str).unwrap_or("{}");
                    ToolCall {
                        id: c.get("id").and_then(Value::as_str).unwrap_or_default().to_string(),
                        name: f
                            .and_then(|f| f.get("name"))
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_string(),
                        // Arguments are a JSON string here. A model that
                        // emits malformed JSON produces an empty object
                        // rather than an error, so the tool can reject it
                        // with a message the model can act on.
                        input: serde_json::from_str(raw).unwrap_or_else(|_| json!({})),
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    let usage = body.get("usage");
    Ok(Completion {
        text,
        thinking,
        calls,
        usage: Usage {
            input_tokens: usage.and_then(|u| u.get("prompt_tokens")).and_then(as_u32),
            output_tokens: usage.and_then(|u| u.get("completion_tokens")).and_then(as_u32),
            cache_read_tokens: None,
        },
        stop_reason: body
            .get("choices")
            .and_then(Value::as_array)
            .and_then(|c| c.first())
            .and_then(|c| c.get("finish_reason"))
            .and_then(Value::as_str)
            .map(str::to_string),
    })
}

fn as_u32(v: &Value) -> Option<u32> {
    v.as_u64().and_then(|n| u32::try_from(n).ok())
}

fn push_para(buf: &mut String, s: Option<&str>) {
    let Some(s) = s else { return };
    if s.is_empty() {
        return;
    }
    if !buf.is_empty() {
        buf.push_str("\n\n");
    }
    buf.push_str(s);
}

/// Header pairs for a request, given the resolved API key.
///
/// Returned rather than applied so the caller can log which headers exist
/// without ever seeing the value — and so this stays testable without a
/// network stack.
pub fn headers(settings: &LlmSettings, api_key: Option<&str>) -> Vec<(&'static str, String)> {
    let mut h = vec![("content-type", "application/json".to_string())];
    match settings.provider {
        ProviderKind::Anthropic => {
            h.push(("anthropic-version", ANTHROPIC_VERSION.to_string()));
            if let Some(k) = api_key.filter(|k| !k.is_empty()) {
                h.push(("x-api-key", k.to_string()));
            }
        }
        ProviderKind::OpenAiCompatible => {
            // Ollama and llama.cpp accept requests with no credential at
            // all, so an absent key is a normal configuration here rather
            // than an error to raise before the request is even attempted.
            if let Some(k) = api_key.filter(|k| !k.is_empty()) {
                h.push(("authorization", format!("Bearer {k}")));
            }
        }
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DataScope;

    fn anthropic() -> LlmSettings {
        LlmSettings {
            enabled: true,
            provider: ProviderKind::Anthropic,
            data_scope: DataScope::SchemaOnly,
            ..Default::default()
        }
    }

    fn openai() -> LlmSettings {
        LlmSettings {
            enabled: true,
            provider: ProviderKind::OpenAiCompatible,
            ..Default::default()
        }
    }

    fn req() -> ChatRequest {
        ChatRequest {
            system: "schema here".into(),
            turns: vec![Turn::User("which processes talk to the internet?".into())],
            tools: vec![ToolSpec {
                name: "run_sql",
                description: "run a read-only query",
                schema: json!({"type":"object","properties":{"sql":{"type":"string"}},"required":["sql"],"additionalProperties":false}),
            }],
        }
    }

    #[test]
    fn urls_follow_the_dialect() {
        assert_eq!(endpoint_url(&anthropic()), "https://api.anthropic.com/v1/messages");
        assert_eq!(endpoint_url(&openai()), "http://localhost:11434/v1/chat/completions");
    }

    #[test]
    fn anthropic_body_has_the_documented_shape() {
        let b = build_body(&anthropic(), &req());
        assert_eq!(b["model"], "claude-opus-5");
        assert_eq!(b["max_tokens"], 16_000);
        assert_eq!(b["system"][0]["text"], "schema here");
        assert_eq!(b["system"][0]["cache_control"]["type"], "ephemeral");
        assert_eq!(b["messages"][0]["role"], "user");
        assert_eq!(b["tools"][0]["input_schema"]["type"], "object");
        assert_eq!(b["tools"][0]["strict"], true);
    }

    #[test]
    fn adaptive_thinking_is_sent_only_where_it_is_accepted() {
        let b = build_body(&anthropic(), &req());
        assert_eq!(b["thinking"]["type"], "adaptive");
        assert_eq!(b["thinking"]["display"], "summarized");
        // budget_tokens was removed on this family; sending it is a 400.
        assert!(b["thinking"].get("budget_tokens").is_none());

        let haiku = LlmSettings { model: "claude-haiku-4-5".into(), ..anthropic() };
        assert!(build_body(&haiku, &req()).get("thinking").is_none());
    }

    #[test]
    fn openai_body_uses_function_tools_and_a_system_message() {
        let b = build_body(&openai(), &req());
        assert_eq!(b["messages"][0]["role"], "system");
        assert_eq!(b["messages"][0]["content"], "schema here");
        assert_eq!(b["tools"][0]["type"], "function");
        assert_eq!(b["tools"][0]["function"]["name"], "run_sql");
        // No `thinking` key in this dialect at all.
        assert!(b.get("thinking").is_none());
    }

    #[test]
    fn tool_results_are_encoded_per_dialect() {
        let turns = vec![
            Turn::User("q".into()),
            Turn::Assistant {
                text: "let me look".into(),
                calls: vec![ToolCall {
                    id: "call_1".into(),
                    name: "run_sql".into(),
                    input: json!({"sql":"SELECT 1"}),
                }],
            },
            Turn::ToolResult {
                id: "call_1".into(),
                name: "run_sql".into(),
                content: "[[1]]".into(),
                is_error: false,
            },
        ];
        let r = ChatRequest { turns, ..req() };

        let a = build_body(&anthropic(), &r);
        assert_eq!(a["messages"][1]["content"][1]["type"], "tool_use");
        assert_eq!(a["messages"][2]["content"][0]["type"], "tool_result");
        assert_eq!(a["messages"][2]["content"][0]["tool_use_id"], "call_1");

        let o = build_body(&openai(), &r);
        // +1 for the system message this dialect puts in `messages`.
        assert_eq!(o["messages"][2]["tool_calls"][0]["function"]["name"], "run_sql");
        // Arguments are a string here, not an object.
        assert!(o["messages"][2]["tool_calls"][0]["function"]["arguments"].is_string());
        assert_eq!(o["messages"][3]["role"], "tool");
    }

    #[test]
    fn anthropic_responses_split_into_text_thinking_and_calls() {
        let body = json!({
            "content": [
                {"type": "thinking", "thinking": "the log has 3 processes"},
                {"type": "text", "text": "Here is what I found."},
                {"type": "tool_use", "id": "toolu_1", "name": "run_sql", "input": {"sql": "SELECT 1"}}
            ],
            "stop_reason": "tool_use",
            "usage": {"input_tokens": 100, "output_tokens": 20, "cache_read_input_tokens": 80}
        });
        let c = parse_response(ProviderKind::Anthropic, &body).unwrap();
        assert_eq!(c.text, "Here is what I found.");
        assert_eq!(c.thinking, "the log has 3 processes");
        assert_eq!(c.calls[0].name, "run_sql");
        assert_eq!(c.calls[0].input["sql"], "SELECT 1");
        assert_eq!(c.usage.cache_read_tokens, Some(80));
        assert!(c.wants_tools());
    }

    #[test]
    fn a_refusal_is_an_error_not_an_empty_answer() {
        // HTTP 200 with stop_reason "refusal". Reading `content` blindly
        // would show the user a blank reply and no reason for it.
        let body = json!({
            "content": [],
            "stop_reason": "refusal",
            "stop_details": {"type": "refusal", "category": "cyber", "explanation": "declined"}
        });
        match parse_response(ProviderKind::Anthropic, &body) {
            Err(LlmError::Refused(why)) => assert_eq!(why, "declined"),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn openai_responses_parse_including_string_arguments() {
        let body = json!({
            "choices": [{
                "message": {
                    "content": "found it",
                    "tool_calls": [{
                        "id": "call_9",
                        "type": "function",
                        "function": {"name": "run_sql", "arguments": "{\"sql\":\"SELECT 2\"}"}
                    }]
                },
                "finish_reason": "tool_calls"
            }],
            "usage": {"prompt_tokens": 5, "completion_tokens": 6}
        });
        let c = parse_response(ProviderKind::OpenAiCompatible, &body).unwrap();
        assert_eq!(c.text, "found it");
        assert_eq!(c.calls[0].input["sql"], "SELECT 2");
        assert_eq!(c.usage.input_tokens, Some(5));
    }

    #[test]
    fn malformed_tool_arguments_do_not_abort_the_turn() {
        // A small local model emitting broken JSON should get a tool error
        // it can correct, not a dead conversation.
        let body = json!({
            "choices": [{"message": {"content": "", "tool_calls": [{
                "id": "c", "type": "function",
                "function": {"name": "run_sql", "arguments": "{not json"}
            }]}}]
        });
        let c = parse_response(ProviderKind::OpenAiCompatible, &body).unwrap();
        assert_eq!(c.calls[0].input, json!({}));
    }

    #[test]
    fn a_shapeless_response_is_a_protocol_error() {
        assert!(matches!(
            parse_response(ProviderKind::Anthropic, &json!({"oops": 1})),
            Err(LlmError::Protocol(_))
        ));
        assert!(matches!(
            parse_response(ProviderKind::OpenAiCompatible, &json!({"choices": []})),
            Err(LlmError::Protocol(_))
        ));
    }

    #[test]
    fn auth_headers_match_the_dialect_and_omit_an_absent_key() {
        let h = headers(&anthropic(), Some("sk-ant-xyz"));
        assert!(h.contains(&("anthropic-version", "2023-06-01".to_string())));
        assert!(h.contains(&("x-api-key", "sk-ant-xyz".to_string())));

        let h = headers(&openai(), Some("sk-openai"));
        assert!(h.contains(&("authorization", "Bearer sk-openai".to_string())));

        // Ollama needs no credential; an empty key must not become
        // "Bearer " or "x-api-key: ".
        let h = headers(&openai(), Some(""));
        assert!(h.iter().all(|(k, _)| *k != "authorization"));
        let h = headers(&anthropic(), None);
        assert!(h.iter().all(|(k, _)| *k != "x-api-key"));
    }
}
