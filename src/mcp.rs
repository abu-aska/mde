use crate::broker::{
    Broker, LocateRequest, PatchRequest, ProjectRequest, TraceRequest, VerifyRequest,
};
use crate::types::{MdeError, MdeResult, MDE_META_NAMESPACE, MDE_VERSION};
use serde_json::{json, Value};
use std::io::{BufRead, Write};

/// Run a newline-delimited JSON-RPC 2.0 stdio MCP server exposing the 5 MDE verbs.
pub fn run_stdio_server<R: BufRead, W: Write>(
    broker: &mut Broker,
    reader: R,
    mut writer: W,
) -> MdeResult<()> {
    for line_res in reader.lines() {
        let line = line_res
            .map_err(|e| MdeError::new("ERR_IO", format!("mcp stdin read error: {e}")))?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let req: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(e) => {
                let resp = json!({
                    "jsonrpc": "2.0",
                    "id": null,
                    "error": {"code": -32700, "message": format!("parse error: {e}")}
                });
                write_json_line(&mut writer, &resp)?;
                continue;
            }
        };

        let id = req.get("id").cloned();
        let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let params = req.get("params").cloned().unwrap_or_else(|| json!({}));

        // JSON-RPC notifications (no id) require no response.
        if id.is_none() {
            continue;
        }
        let req_id = id.unwrap();

        let response = match method {
            "initialize" => json!({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "serverInfo": {
                        "name": "mde",
                        "version": MDE_VERSION
                    },
                    "capabilities": {
                        "tools": {}
                    },
                    "_meta": {
                        MDE_META_NAMESPACE: {
                            "profile": "A+B-meta",
                            "read_before_write_lock": true
                        }
                    }
                }
            }),
            "ping" => json!({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {}
            }),
            "tools/list" => json!({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "tools": tool_definitions()
                }
            }),
            "tools/call" => handle_tool_call(broker, req_id, &params),
            _ => json!({
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32601,
                    "message": format!("method not found: {method}")
                }
            }),
        };

        write_json_line(&mut writer, &response)?;
    }
    Ok(())
}

fn write_json_line<W: Write>(writer: &mut W, value: &Value) -> MdeResult<()> {
    let encoded = serde_json::to_string(value)
        .map_err(|e| MdeError::new("ERR_SERIALIZE", format!("mcp encode error: {e}")))?;
    writeln!(writer, "{encoded}")
        .map_err(|e| MdeError::new("ERR_IO", format!("mcp stdout write error: {e}")))?;
    writer
        .flush()
        .map_err(|e| MdeError::new("ERR_IO", format!("mcp stdout flush error: {e}")))
}

fn handle_tool_call(broker: &mut Broker, req_id: Value, params: &Value) -> Value {
    let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let args = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));

    let outcome: MdeResult<Value> = match name {
        "splice_locate" => serde_json::from_value::<LocateRequest>(args)
            .map_err(|e| MdeError::new("ERR_INVALID_ARGS", format!("{e}")))
            .and_then(|r| broker.splice_locate(r))
            .and_then(to_json_value),
        "splice_trace" => serde_json::from_value::<TraceRequest>(args)
            .map_err(|e| MdeError::new("ERR_INVALID_ARGS", format!("{e}")))
            .and_then(|r| broker.splice_trace(r))
            .and_then(to_json_value),
        "splice_patch" => serde_json::from_value::<PatchRequest>(args)
            .map_err(|e| MdeError::new("ERR_INVALID_ARGS", format!("{e}")))
            .and_then(|r| broker.splice_patch(r))
            .and_then(to_json_value),
        "splice_verify" => serde_json::from_value::<VerifyRequest>(args)
            .map_err(|e| MdeError::new("ERR_INVALID_ARGS", format!("{e}")))
            .and_then(|r| broker.splice_verify(r))
            .and_then(to_json_value),
        "splice_project" => serde_json::from_value::<ProjectRequest>(args)
            .map_err(|e| MdeError::new("ERR_INVALID_ARGS", format!("{e}")))
            .and_then(|r| broker.splice_project(r))
            .and_then(to_json_value),
        _ => Err(MdeError::new(
            "ERR_UNKNOWN_TOOL",
            format!("unknown tool: {name}"),
        )),
    };

    match outcome {
        Ok(payload) => {
            let meta = payload.get("_meta").cloned();
            let text = serde_json::to_string(&payload).unwrap_or_default();
            let mut result = json!({
                "content": [{"type": "text", "text": text}],
                "structuredContent": payload,
                "isError": false
            });
            if let Some(m) = meta {
                result["_meta"] = m;
            }
            json!({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": result
            })
        }
        Err(err) => {
            let err_val = serde_json::to_value(&err).unwrap_or_else(|_| json!({"code": err.code}));
            json!({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": serde_json::to_string(&err_val).unwrap_or_default()}],
                    "structuredContent": err_val,
                    "isError": true
                }
            })
        }
    }
}

fn to_json_value<T: serde::Serialize>(val: T) -> MdeResult<Value> {
    serde_json::to_value(val).map_err(|e| MdeError::new("ERR_SERIALIZE", format!("{e}")))
}

fn tool_definitions() -> Value {
    json!([
        {
            "name": "splice_locate",
            "description": "Parse a file with Tree-sitter CST, return byte spans and syntactic zone tags, and mint session read_token values.",
            "inputSchema": {
                "type": "object",
                "required": ["path"],
                "properties": {
                    "path": {"type": "string"},
                    "capability_id": {"type": "string"}
                }
            }
        },
        {
            "name": "splice_trace",
            "description": "Trace static references, mapped anchors, unresolved dynamic sites, risk triggers, and syntactic zones.",
            "inputSchema": {
                "type": "object",
                "required": ["path"],
                "properties": {
                    "path": {"type": "string"},
                    "symbol": {"type": "string"}
                }
            }
        },
        {
            "name": "splice_patch",
            "description": "Validate read_token lock, syntax/macro safety, and oracle protection, then emit a content-addressed Splice Packet.",
            "inputSchema": {
                "type": "object",
                "required": ["capability_id", "read_tokens", "edits"],
                "properties": {
                    "capability_id": {"type": "string"},
                    "read_tokens": {"type": "array", "items": {"type": "string"}},
                    "edits": {"type": "array", "items": {"type": "object"}},
                    "commit_subject": {"type": "string"},
                    "summary_lines": {"type": "array", "items": {"type": "string"}},
                    "allow_oracle_write": {"type": "boolean"}
                }
            }
        },
        {
            "name": "splice_verify",
            "description": "Verify a Splice Packet inside an isolated workspace with oracle tamper detection and secret scanning.",
            "inputSchema": {
                "type": "object",
                "required": ["packet_id"],
                "properties": {
                    "packet_id": {"type": "string"},
                    "eval_count": {"type": "integer"}
                }
            }
        },
        {
            "name": "splice_project",
            "description": "Project a verified Splice Packet and Evidence Bundle into a minimal standard Git commit.",
            "inputSchema": {
                "type": "object",
                "required": ["packet_id", "bundle_id"],
                "properties": {
                    "packet_id": {"type": "string"},
                    "bundle_id": {"type": "string"},
                    "approve_diff_sha256": {"type": "string"}
                }
            }
        }
    ])
}
