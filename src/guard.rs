use crate::policy::{
    confine_path, scan_secrets_and_paths, validate_call_policy, PolicyConfig,
};
use crate::types::{MdeError, MdeResult};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

pub const DEFAULT_MAX_PARAGRAPH_CHARS: usize = 420;
const EM_DASH: char = '\u{2014}';

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardFinding {
    pub path: String,
    pub line: usize,
    pub rule: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardReport {
    pub passed: bool,
    pub files_checked: usize,
    pub total_lines: usize,
    pub dupes_checked: bool,
    pub secret_scan_passed: bool,
    pub findings: Vec<GuardFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardOptions {
    #[serde(default = "default_true")]
    pub check_prose: bool,
    #[serde(default = "default_true")]
    pub check_dupes: bool,
    #[serde(default = "default_true")]
    pub check_secrets: bool,
    #[serde(default)]
    pub check_mentions: bool,
    #[serde(default = "default_max_para")]
    pub max_paragraph_chars: usize,
    #[serde(default = "default_max_bytes")]
    pub max_trace_bytes: usize,
    #[serde(default)]
    pub extra_forbidden_patterns: Vec<String>,
}

fn default_true() -> bool {
    true
}

fn default_max_para() -> usize {
    DEFAULT_MAX_PARAGRAPH_CHARS
}

fn default_max_bytes() -> usize {
    1_048_576
}

impl Default for GuardOptions {
    fn default() -> Self {
        Self {
            check_prose: true,
            check_dupes: true,
            check_secrets: true,
            check_mentions: false,
            max_paragraph_chars: DEFAULT_MAX_PARAGRAPH_CHARS,
            max_trace_bytes: 1_048_576,
            extra_forbidden_patterns: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct CallPolicyRequest {
    pub verb: String,
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default = "default_one")]
    pub eval_count: u64,
    #[serde(default)]
    pub allow_oracle_write: bool,
}

fn default_one() -> u64 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallPolicyReport {
    pub allowed: bool,
    pub verb: String,
    pub normalized_paths: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rejection: Option<MdeError>,
}

const BANNED_AI_TELLS: &[&str] = &[
    // Frame openers and announcement frames
    r"(?i)two things worth stating",
    r"(?i)findings first",
    r"(?i)the honest gap",
    r"(?i)i want to be upfront",
    r"(?i)one caveat worth flagging",
    r"(?i)two notes for",
    r"(?i)note on mechanism",
    r"(?i)a few thoughts",
    r"(?i)worth settling",
    r"(?i)worth pinning down",
    r"(?i)something to consider",
    r"(?i)stated plainly",
    r"(?i)to put it plainly",
    // Cardinality prefaces
    r"(?i)\b(two|three|four|five) ([a-z]+ ){0,3}(notes|points|things|thoughts|observations|findings)[.:]",
    r"(?im)^one ([a-z]+ ){1,4}notes?\s*[:.]",
    r"(?im)^a quick note\b",
    // Self-referential meta-framing
    r"(?i)i'?d frame this differently",
    r"(?i)i'?d argue",
    r"(?i)i would say",
    r"(?i)my earlier note",
    r"(?i)this deserves",
    r"(?i)stand on their own",
    r"(?i)deserves precision",
    // Search narration
    r"(?i)after tracing",
    r"(?i)it turns out that",
    r"(?i)i checked .{0,20} and found",
    // Unsolicited verdicts
    r"(?i)the right shape",
    r"(?i)right design",
    r"(?i)exactly what is needed",
    r"(?i)the natural single base",
    r"(?i)the obvious choice",
    r"(?i)a step in the right direction",
    // Condescending praise
    r"(?i)the strongest evidence",
    r"(?i)the strongest proof",
    r"(?i)the strongest signal",
    r"(?i)the best datapoint",
    r"(?i)the best data point",
    r"(?i)the best report",
    r"(?i)the best analysis",
    r"(?i)the cleanest proof",
    // Signposts and filler closers
    r"(?im)^notably\b",
    r"(?im)^importantly\b",
    r"(?im)^it is worth noting\b",
    r"(?im)^at its core\b",
    r"(?i)that is okay",
    r"(?i)no shame",
    r"(?i)none subsumes another",
    r"(?i)the rest follows",
    r"(?i)nothing else to add",
];

const OUTCOME_FORECASTS: &[&str] = &[
    r"(?i)\bafter this lands\b",
    r"(?i)\bonce this ships\b",
    r"(?i)\bwhen this merges\b",
    r"(?i)\bif this lands\b",
    r"(?i)\bshould be closed\b",
    r"(?i)\bready to merge\b",
];

/// Strip fenced code blocks and inline backticks while preserving exact line numbers.
pub fn strip_code_preserving_lines(raw: &str) -> String {
    let inline_re = Regex::new(r"`[^`]*`").expect("valid inline regex");
    let mut out = Vec::new();
    let mut in_fence = false;
    for line in raw.lines() {
        if line.trim_start().starts_with("```") {
            in_fence = !in_fence;
            out.push(String::new());
            continue;
        }
        if in_fence {
            out.push(String::new());
        } else {
            out.push(inline_re.replace_all(line, "").into_owned());
        }
    }
    out.join("\n")
}

/// Run deterministic prose, duplicate-reference, forecast, and secret/path checks on in-memory sources.
pub fn check_sources(sources: &[(&str, &str)], opts: &GuardOptions) -> GuardReport {
    let mut findings = Vec::new();
    let mut total_lines = 0usize;
    let mut secret_scan_passed = true;

    for (name, raw) in sources {
        total_lines += raw.lines().count();

        if opts.check_secrets {
            let scan = scan_secrets_and_paths(raw.as_bytes(), opts.max_trace_bytes);
            if !scan.passed {
                secret_scan_passed = false;
                for item in scan.findings {
                    findings.push(GuardFinding {
                        path: (*name).to_string(),
                        line: 1,
                        rule: "secret_or_path_leak".to_string(),
                        message: format!("secret, local path, or trace size violation: {item}"),
                    });
                }
            }
        }

        if opts.check_prose {
            check_prose_rules(name, raw, opts, &mut findings);
        }

        if opts.check_dupes {
            check_duplicate_refs(name, raw, &mut findings);
        }
    }

    GuardReport {
        passed: findings.is_empty(),
        files_checked: sources.len(),
        total_lines,
        dupes_checked: opts.check_dupes,
        secret_scan_passed,
        findings,
    }
}

/// Run guard checks across file paths on disk.
pub fn check_files(paths: &[String], opts: &GuardOptions) -> MdeResult<GuardReport> {
    let mut loaded: Vec<(String, String)> = Vec::with_capacity(paths.len());
    for p in paths {
        let raw = fs::read_to_string(p)
            .map_err(|e| MdeError::new("ERR_IO", format!("guard failed to read {p}: {e}")))?;
        loaded.push((p.clone(), raw));
    }
    let refs: Vec<(&str, &str)> = loaded
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    Ok(check_sources(&refs, opts))
}

fn check_prose_rules(name: &str, raw: &str, opts: &GuardOptions, findings: &mut Vec<GuardFinding>) {
    let prose = strip_code_preserving_lines(raw);

    for (idx, line) in prose.lines().enumerate() {
        let line_no = idx + 1;
        if line.contains(EM_DASH) {
            findings.push(GuardFinding {
                path: name.to_string(),
                line: line_no,
                rule: "em_dash".to_string(),
                message: format!(
                    "em dash in prose (use period or comma): {}",
                    line.trim().chars().take(100).collect::<String>()
                ),
            });
        }
        if line.contains(';') && line.chars().count() > 60 {
            findings.push(GuardFinding {
                path: name.to_string(),
                line: line_no,
                rule: "clause_semicolon".to_string(),
                message: format!(
                    "semicolon stitching long clause: {}",
                    line.trim().chars().take(100).collect::<String>()
                ),
            });
        }
        if line.chars().count() > opts.max_paragraph_chars && !line.trim_start().starts_with('|') {
            findings.push(GuardFinding {
                path: name.to_string(),
                line: line_no,
                rule: "long_paragraph".to_string(),
                message: format!(
                    "paragraph exceeds {} chars ({} chars)",
                    opts.max_paragraph_chars,
                    line.chars().count()
                ),
            });
        }
    }

    for pat in BANNED_AI_TELLS {
        if let Ok(re) = Regex::new(pat) {
            for m in re.find_iter(&prose) {
                let line_no = byte_offset_to_line(&prose, m.start());
                findings.push(GuardFinding {
                    path: name.to_string(),
                    line: line_no,
                    rule: "ai_tell".to_string(),
                    message: format!("banned AI-tell phrase '{}'", m.as_str()),
                });
            }
        }
    }

    for pat in OUTCOME_FORECASTS {
        if let Ok(re) = Regex::new(pat) {
            for m in re.find_iter(&prose) {
                let line_no = byte_offset_to_line(&prose, m.start());
                findings.push(GuardFinding {
                    path: name.to_string(),
                    line: line_no,
                    rule: "outcome_forecast".to_string(),
                    message: format!("outcome forecast or close directive '{}'", m.as_str()),
                });
            }
        }
    }

    for pat in &opts.extra_forbidden_patterns {
        if let Ok(re) = Regex::new(pat) {
            for m in re.find_iter(raw) {
                let line_no = byte_offset_to_line(raw, m.start());
                findings.push(GuardFinding {
                    path: name.to_string(),
                    line: line_no,
                    rule: "custom_forbidden".to_string(),
                    message: format!("matched forbidden pattern '{}'", m.as_str()),
                });
            }
        }
    }

    if opts.check_mentions {
        let mention_re = Regex::new(r"(^|[^\w.@])(@[A-Za-z0-9_][A-Za-z0-9_-]*)").expect("valid");
        for cap in mention_re.captures_iter(&prose) {
            if let Some(m) = cap.get(2) {
                let line_no = byte_offset_to_line(&prose, m.start());
                findings.push(GuardFinding {
                    path: name.to_string(),
                    line: line_no,
                    rule: "mention_candidate".to_string(),
                    message: format!("standalone @-mention '{}' (verify not self-ping)", m.as_str()),
                });
            }
        }
    }
}

fn check_duplicate_refs(name: &str, raw: &str, findings: &mut Vec<GuardFinding>) {
    let url_re = Regex::new(r"(?i)https?://\S+").expect("valid url regex");
    let gh_url_re =
        Regex::new(r"(?i)github\.com/[^/\s]+/[^/\s]+/(?:pull|issues)/(\d+)").expect("valid gh");
    let ref_re = Regex::new(r"(?i)(?:PR|issue)?\s*#(\d+)").expect("valid ref regex");

    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut first_line: BTreeMap<String, usize> = BTreeMap::new();
    let mut seen_forms: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut url_spans: Vec<(usize, usize)> = Vec::new();

    let mut record = |key: String, form: String, pos: usize| {
        *counts.entry(key.clone()).or_insert(0) += 1;
        first_line
            .entry(key.clone())
            .or_insert_with(|| byte_offset_to_line(raw, pos));
        let forms = seen_forms.entry(key).or_default();
        if !forms.contains(&form) {
            forms.push(form);
        }
    };

    for m in url_re.find_iter(raw) {
        url_spans.push((m.start(), m.end()));
        let trimmed = m
            .as_str()
            .trim_end_matches(['.', ',', ';', ':', '!', '?', '\'', '"', '`', ')', ']', '}', '>']);
        if let Some(cap) = gh_url_re.captures(trimmed) {
            let num = cap.get(1).map(|g| g.as_str()).unwrap_or("");
            record(format!("gh#{num}"), trimmed.to_string(), m.start());
        } else {
            let key = normalize_url_key(trimmed);
            record(key, trimmed.to_string(), m.start());
        }
    }

    for cap in ref_re.captures_iter(raw) {
        let full = cap.get(0).unwrap();
        if url_spans
            .iter()
            .any(|(s, e)| full.start() >= *s && full.start() < *e)
        {
            continue;
        }
        let num = cap.get(1).map(|g| g.as_str()).unwrap_or("");
        record(
            format!("gh#{num}"),
            full.as_str().trim().to_string(),
            full.start(),
        );
    }

    for (key, count) in counts {
        if count > 1 {
            let line = *first_line.get(&key).unwrap_or(&1);
            let forms = seen_forms
                .get(&key)
                .map(|v| v.join(", "))
                .unwrap_or_else(|| key.clone());
            findings.push(GuardFinding {
                path: name.to_string(),
                line,
                rule: "duplicate_reference".to_string(),
                message: format!("duplicate reference '{key}' appears {count}x (seen: {forms})"),
            });
        }
    }
}

fn normalize_url_key(url: &str) -> String {
    let lower = url.to_lowercase();
    let without_frag = lower.split('#').next().unwrap_or(&lower);
    let without_query = without_frag.split('?').next().unwrap_or(without_frag);
    without_query.trim_end_matches('/').to_string()
}

fn byte_offset_to_line(text: &str, offset: usize) -> usize {
    let clamped = offset.min(text.len());
    text[..clamped].bytes().filter(|b| *b == b'\n').count() + 1
}

/// Evaluate safeagents-style call policy (verb allowlist, path confinement, oracle lock, budget).
pub fn evaluate_call_policy(
    repo_root: &Path,
    req: &CallPolicyRequest,
    policy: &PolicyConfig,
) -> CallPolicyReport {
    let mut normalized_paths = Vec::with_capacity(req.paths.len());
    for raw_path in &req.paths {
        match confine_path(repo_root, raw_path) {
            Ok((norm, _)) => normalized_paths.push(norm),
            Err(err) => {
                return CallPolicyReport {
                    allowed: false,
                    verb: req.verb.clone(),
                    normalized_paths,
                    rejection: Some(err),
                };
            }
        }
    }

    match validate_call_policy(
        &req.verb,
        &normalized_paths,
        req.eval_count,
        req.allow_oracle_write,
        policy,
    ) {
        Ok(()) => CallPolicyReport {
            allowed: true,
            verb: req.verb.clone(),
            normalized_paths,
            rejection: None,
        },
        Err(err) => CallPolicyReport {
            allowed: false,
            verb: req.verb.clone(),
            normalized_paths,
            rejection: Some(err),
        },
    }
}
