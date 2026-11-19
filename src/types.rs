use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;

pub const MDE_META_NAMESPACE: &str = "gg.siliconcordat/mde";
pub const SPLICE_PACKET_SCHEMA: &str = "splice-packet/v0.1";
pub const EVIDENCE_BUNDLE_SCHEMA: &str = "evidence-bundle/v0.1";
pub const MDE_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Zone {
    Prose,
    Code,
    FormalProof,
    UiModule,
}

impl Zone {
    pub fn as_str(&self) -> &'static str {
        match self {
            Zone::Prose => "prose",
            Zone::Code => "code",
            Zone::FormalProof => "formal_proof",
            Zone::UiModule => "ui_module",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Language {
    Rust,
    Python,
    C,
    Typescript,
    Tsx,
    Markdown,
    Lean,
    UiText,
    Plain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Lane {
    Build,
    Record,
    Idea,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskClass {
    Routine,
    HighRisk,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByteSpan {
    pub start_byte: usize,
    pub end_byte: usize,
    pub start_line: usize,
    pub end_line: usize,
    pub kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocatedSymbol {
    pub symbol: String,
    pub kind: String,
    pub zone: Zone,
    pub start_byte: usize,
    pub end_byte: usize,
    pub start_line: usize,
    pub end_line: usize,
    pub span_sha256: String,
    pub read_token: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DynamicSite {
    pub path: String,
    pub line: usize,
    pub kind: String,
    pub snippet: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MdeMetaPayload {
    pub zone_hint: Zone,
    pub dominant_zone: Zone,
    pub zone_bytes: BTreeMap<String, usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checkpoint_fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slot_manifest_digest: Option<String>,
    pub rollback_state: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocateResult {
    pub path: String,
    pub language: Language,
    pub blob_sha256: String,
    pub cst_root_sha256: String,
    pub total_bytes: usize,
    pub file_read_token: String,
    pub dominant_zone: Zone,
    pub symbols: Vec<LocatedSymbol>,
    pub error_spans: Vec<ByteSpan>,
    pub macro_opaque_spans: Vec<ByteSpan>,
    #[serde(rename = "_meta")]
    pub meta: BTreeMap<String, MdeMetaPayload>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReferenceHit {
    pub path: String,
    pub line: usize,
    pub snippet: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceResult {
    pub path: String,
    pub symbol: Option<String>,
    pub blob_sha256: String,
    pub file_read_token: String,
    pub dominant_zone: Zone,
    pub references: Vec<ReferenceHit>,
    pub mapped_anchors: Vec<String>,
    pub widened_anchors: Vec<String>,
    pub unresolved_dynamic_sites: Vec<DynamicSite>,
    pub risk_class: RiskClass,
    pub risk_triggers: Vec<String>,
    #[serde(rename = "_meta")]
    pub meta: BTreeMap<String, MdeMetaPayload>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadProof {
    pub path: String,
    pub blob_sha256: String,
    pub cst_root_sha256: String,
    pub read_token: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CstEdit {
    pub path: String,
    pub language: Language,
    pub anchor_node_kind: String,
    pub anchor_symbol: String,
    pub zone: Zone,
    pub start_byte: usize,
    pub end_byte: usize,
    pub expected_old_sha256: String,
    pub replacement_utf8: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeamContract {
    pub exported_symbols_touched: Vec<String>,
    pub calls_added: Vec<String>,
    pub unresolved_dynamic_sites: Vec<String>,
    pub declared_effects: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetUsed {
    pub tokens: u64,
    pub evals: u64,
    pub wall_sec: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenerationProvenance {
    pub actor: String,
    pub mode: String,
    pub model_id: String,
    pub prompt_sha256: Option<String>,
    pub tool_trace_sha256: Option<String>,
    pub budget_used: BudgetUsed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitProjectionSpec {
    pub commit_subject: String,
    pub summary_lines: Vec<String>,
    pub expected_result_tree: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplicePacket {
    pub schema: String,
    pub packet_id: String,
    pub capability_id: String,
    pub base_commit: String,
    pub base_tree: String,
    pub lane: Lane,
    pub risk_class: RiskClass,
    pub risk_triggers: Vec<String>,
    pub parent_packets: Vec<String>,
    pub read_proofs: Vec<ReadProof>,
    pub edits: Vec<CstEdit>,
    pub seam_contract: SeamContract,
    pub generation_provenance: GenerationProvenance,
    pub git_projection: GitProjectionSpec,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolchainDigest {
    pub os: String,
    pub arch: String,
    pub mde_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleIntegrity {
    pub protected_paths_pre_sha256: String,
    pub protected_paths_post_sha256: String,
    pub tamper_free: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandResult {
    pub zone: String,
    pub cmd: Vec<String>,
    pub exit_code: i32,
    pub duration_ms: u64,
    pub diagnostics_sha256: String,
    pub passed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorResult {
    pub anchor_id: String,
    pub tier: u8,
    pub visibility: String,
    pub zone: String,
    pub cmd: Vec<String>,
    pub exit_code: i32,
    pub passed: bool,
    pub duration_ms: u64,
    pub stdout_sha256: String,
    pub stderr_sha256: String,
    pub cassette_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceSummary {
    pub tier0_pass: bool,
    pub tier1_passed: usize,
    pub tier1_total: usize,
    pub lexicase_grade: String,
    pub widened_for_unresolved_sites: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretScanResult {
    pub passed: bool,
    pub max_trace_bytes: usize,
    pub actual_trace_bytes: usize,
    pub findings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HumanApproval {
    pub required: bool,
    pub approved_diff_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceBundle {
    pub schema: String,
    pub bundle_id: String,
    pub packet_id: String,
    pub base_tree: String,
    pub result_tree: String,
    pub toolchain_digest: ToolchainDigest,
    pub oracle_integrity: OracleIntegrity,
    pub tier0_compiler: CommandResult,
    pub anchors: Vec<AnchorResult>,
    pub summary: EvidenceSummary,
    pub secret_scan: SecretScanResult,
    pub human_approval: HumanApproval,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectResult {
    pub packet_id: String,
    pub bundle_id: String,
    pub commit_sha: String,
    pub diff_sha256: String,
    pub touched_files: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MdeError {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<Value>,
}

impl MdeError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            detail: None,
        }
    }

    pub fn with_detail(
        code: impl Into<String>,
        message: impl Into<String>,
        detail: Value,
    ) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            detail: Some(detail),
        }
    }
}

impl fmt::Display for MdeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for MdeError {}

pub type MdeResult<T> = Result<T, MdeError>;

pub fn sha256_prefixed(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

pub fn canonicalize_json(val: &Value) -> Value {
    match val {
        Value::Object(map) => {
            let mut sorted: BTreeMap<String, Value> = BTreeMap::new();
            for (k, v) in map {
                sorted.insert(k.clone(), canonicalize_json(v));
            }
            let mut out = Map::new();
            for (k, v) in sorted {
                out.insert(k, v);
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(canonicalize_json).collect()),
        _ => val.clone(),
    }
}

pub fn canonical_json_sha256<T: Serialize>(value: &T, omit_field: Option<&str>) -> MdeResult<String> {
    let mut raw = serde_json::to_value(value)
        .map_err(|e| MdeError::new("ERR_SERIALIZE", format!("json serialize error: {e}")))?;
    if let (Some(field), Value::Object(map)) = (omit_field, &mut raw) {
        map.remove(field);
    }
    let canonical = canonicalize_json(&raw);
    let encoded = serde_json::to_vec(&canonical)
        .map_err(|e| MdeError::new("ERR_SERIALIZE", format!("canonical encode error: {e}")))?;
    Ok(sha256_prefixed(&encoded))
}
