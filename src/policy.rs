use crate::types::{MdeError, MdeResult, RiskClass, SecretScanResult};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fs;
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorSpec {
    pub anchor_id: String,
    pub tier: u8,
    pub visibility: String,
    pub zone: String,
    pub cmd: Vec<String>,
    #[serde(default)]
    pub path_prefixes: Vec<String>,
    #[serde(default)]
    pub cassette_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    pub protected_oracle_paths: Vec<String>,
    pub high_risk_prefixes: Vec<String>,
    pub allowed_verbs: Vec<String>,
    pub max_evals: u64,
    pub max_wall_sec: u64,
    pub max_trace_bytes: usize,
    #[serde(default)]
    pub tier0_cmd: Option<Vec<String>>,
    #[serde(default)]
    pub anchors: Vec<AnchorSpec>,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            protected_oracle_paths: vec![
                "tests/".to_string(),
                "anchors/".to_string(),
                ".mde/anchors.json".to_string(),
                ".mde/policy.json".to_string(),
            ],
            high_risk_prefixes: vec![
                "auth/".to_string(),
                "security/".to_string(),
                "schema/".to_string(),
                "migrations/".to_string(),
                "infra/".to_string(),
                ".github/".to_string(),
                "anchors/".to_string(),
                "tests/".to_string(),
            ],
            allowed_verbs: vec![
                "splice_locate".to_string(),
                "splice_trace".to_string(),
                "splice_patch".to_string(),
                "splice_verify".to_string(),
                "splice_project".to_string(),
            ],
            max_evals: 8,
            max_wall_sec: 30,
            max_trace_bytes: 1_048_576,
            tier0_cmd: None,
            anchors: Vec::new(),
        }
    }
}

impl PolicyConfig {
    pub fn load(repo_root: &Path) -> MdeResult<Self> {
        let policy_path = repo_root.join(".mde/policy.json");
        if !policy_path.exists() {
            return Ok(Self::default());
        }
        let raw = fs::read_to_string(&policy_path).map_err(|e| {
            MdeError::new(
                "ERR_POLICY_LOAD",
                format!("failed to read .mde/policy.json: {e}"),
            )
        })?;
        serde_json::from_str(&raw).map_err(|e| {
            MdeError::new(
                "ERR_POLICY_LOAD",
                format!("invalid .mde/policy.json: {e}"),
            )
        })
    }
}

/// Normalize and confine a repository-relative path inside `repo_root`.
/// Rejects absolute paths, parent traversal, NUL bytes, and symlinks escaping `repo_root`.
pub fn confine_path(repo_root: &Path, rel_path: &str) -> MdeResult<(String, PathBuf)> {
    if rel_path.is_empty() || rel_path.contains('\0') {
        return Err(MdeError::new(
            "ERR_PATH_OUT_OF_BOUNDS",
            "empty or NUL-containing path",
        ));
    }
    let candidate = Path::new(rel_path);
    if candidate.is_absolute() {
        return Err(MdeError::new(
            "ERR_PATH_OUT_OF_BOUNDS",
            format!("absolute path rejected: {rel_path}"),
        ));
    }

    let mut clean_parts: Vec<String> = Vec::new();
    for comp in candidate.components() {
        match comp {
            Component::Normal(seg) => {
                let s = seg.to_string_lossy().into_owned();
                if s == ".git" {
                    return Err(MdeError::new(
                        "ERR_PATH_OUT_OF_BOUNDS",
                        "direct .git access is forbidden",
                    ));
                }
                clean_parts.push(s);
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(MdeError::new(
                    "ERR_PATH_OUT_OF_BOUNDS",
                    format!("path traversal rejected: {rel_path}"),
                ));
            }
        }
    }

    if clean_parts.is_empty() {
        return Err(MdeError::new(
            "ERR_PATH_OUT_OF_BOUNDS",
            "path resolves to repository root",
        ));
    }

    let normalized = clean_parts.join("/");
    let joined = repo_root.join(&normalized);
    let canon_root = fs::canonicalize(repo_root).map_err(|e| {
        MdeError::new(
            "ERR_PATH_OUT_OF_BOUNDS",
            format!("cannot canonicalize repo root: {e}"),
        )
    })?;

    // Check symlink containment for existing paths or existing ancestor directories.
    let mut probe = joined.as_path();
    while !probe.exists() {
        match probe.parent() {
            Some(p) => probe = p,
            None => break,
        }
    }
    if probe.exists() {
        let canon_probe = fs::canonicalize(probe).map_err(|e| {
            MdeError::new(
                "ERR_PATH_OUT_OF_BOUNDS",
                format!("cannot canonicalize path ancestor: {e}"),
            )
        })?;
        if !canon_probe.starts_with(&canon_root) {
            return Err(MdeError::new(
                "ERR_PATH_OUT_OF_BOUNDS",
                format!("symlink escape rejected: {normalized}"),
            ));
        }
    }

    Ok((normalized, joined))
}

pub fn is_protected_oracle_path(normalized_path: &str, policy: &PolicyConfig) -> bool {
    for prefix in &policy.protected_oracle_paths {
        if prefix.ends_with('/') {
            if normalized_path.starts_with(prefix) {
                return true;
            }
        } else if normalized_path == prefix {
            return true;
        }
    }
    let file_name = Path::new(normalized_path)
        .file_name()
        .map(|s| s.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    file_name.starts_with("test_")
        || file_name.ends_with("_test.rs")
        || file_name.ends_with("_test.py")
        || file_name.ends_with("_test.c")
        || file_name.ends_with(".test.ts")
        || file_name.ends_with(".spec.ts")
}

pub fn classify_risk(
    paths: &[String],
    exported_symbols: &[String],
    capability_id: &str,
    policy: &PolicyConfig,
) -> (RiskClass, Vec<String>) {
    let mut triggers: Vec<String> = Vec::new();
    for path in paths {
        let lower = path.to_lowercase();
        if lower.contains("auth") || lower.contains("security") || lower.contains("secret") {
            push_unique(&mut triggers, "auth");
        }
        if lower.contains("schema") || lower.contains("migration") || lower.ends_with(".sql") {
            push_unique(&mut triggers, "schema");
        }
        if lower.starts_with("infra/") || lower.starts_with(".github/") || lower == "dockerfile" {
            push_unique(&mut triggers, "infra");
        }
        if is_protected_oracle_path(path, policy) {
            push_unique(&mut triggers, "anchors");
        }
        for prefix in &policy.high_risk_prefixes {
            if path.starts_with(prefix) {
                push_unique(&mut triggers, prefix.trim_end_matches('/'));
            }
        }
    }
    if capability_id == "anchor_spec_change" {
        push_unique(&mut triggers, "anchors");
    }
    if exported_symbols
        .iter()
        .any(|s| s.starts_with("pub ") || s.contains("PUBLIC_API"))
    {
        push_unique(&mut triggers, "public_api");
    }
    let class = if triggers.is_empty() {
        RiskClass::Routine
    } else {
        RiskClass::HighRisk
    };
    (class, triggers)
}

fn push_unique(list: &mut Vec<String>, value: &str) {
    if !list.iter().any(|item| item == value) {
        list.push(value.to_string());
    }
}

/// Deterministic safeagents-style call validator executed before any broker verb runs.
pub fn validate_call_policy(
    verb: &str,
    paths: &[String],
    eval_count: u64,
    allow_oracle_write: bool,
    policy: &PolicyConfig,
) -> MdeResult<()> {
    if !policy.allowed_verbs.iter().any(|v| v == verb) {
        return Err(MdeError::new(
            "ERR_POLICY_DENIED",
            format!("verb not permitted by policy: {verb}"),
        ));
    }
    if eval_count > policy.max_evals {
        return Err(MdeError::with_detail(
            "ERR_BUDGET_EXCEEDED",
            format!("eval count {eval_count} exceeds max_evals {}", policy.max_evals),
            json!({"eval_count": eval_count, "max_evals": policy.max_evals}),
        ));
    }
    if verb == "splice_patch" && !allow_oracle_write {
        for path in paths {
            if is_protected_oracle_path(path, policy) {
                return Err(MdeError::with_detail(
                    "ERR_PROTECTED_ORACLE",
                    format!("protected test or anchor path cannot be edited: {path}"),
                    json!({"path": path}),
                ));
            }
        }
    }
    Ok(())
}

/// Fail-closed secret, token, private-key, and local home-directory path scanner (Gate G6.4).
pub fn scan_secrets_and_paths(data: &[u8], max_bytes: usize) -> SecretScanResult {
    let mut findings: Vec<String> = Vec::new();
    let actual_trace_bytes = data.len();
    if actual_trace_bytes > max_bytes {
        findings.push(format!(
            "trace_size_exceeded:{actual_trace_bytes}>{max_bytes}"
        ));
    }

    let text = String::from_utf8_lossy(data);
    let patterns: &[(&str, &str)] = &[
        ("private_key_pem", r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
        ("aws_access_key", r"\bAKIA[0-9A-Z]{16}\b"),
        ("github_token", r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b"),
        ("github_pat", r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
        ("api_sk_token", r"\bsk-(?:live|test|proj|ant)-[A-Za-z0-9_\-]{16,}\b"),
        ("local_macos_home", r"/Users/[A-Za-z0-9._-]+/"),
        ("local_linux_home", r"/home/[A-Za-z0-9._-]+/"),
        ("local_windows_home", r"[A-Za-z]:\\Users\\[A-Za-z0-9._-]+\\"),
    ];

    for (label, pat) in patterns {
        if let Ok(re) = Regex::new(pat) {
            if re.is_match(&text) {
                findings.push((*label).to_string());
            }
        }
    }

    SecretScanResult {
        passed: findings.is_empty(),
        max_trace_bytes: max_bytes,
        actual_trace_bytes,
        findings,
    }
}
