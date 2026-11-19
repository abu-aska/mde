use mde::broker::{
    Broker, GuardRequest, LocateRequest, PatchEditInput, PatchRequest, VerifyRequest,
};
use mde::cst::{analyze_file, apply_byte_span_edits};
use mde::guard::{
    check_files, check_sources, evaluate_call_policy, CallPolicyRequest, GuardOptions,
};
use mde::policy::PolicyConfig;
use mde::types::{sha256_prefixed, Zone, MDE_META_NAMESPACE};
use mde::zone_manifest::{build_zone_manifest, verify_zone_manifest_file};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn copy_fixture_into_temp(tmp: &Path, fixture_rel: &str, dest_rel: &str) -> Vec<u8> {
    let src = repo_root().join(fixture_rel);
    let bytes = fs::read(&src).expect("read fixture");
    let dest = tmp.join(dest_rel);
    if let Some(p) = dest.parent() {
        fs::create_dir_all(p).unwrap();
    }
    fs::write(&dest, &bytes).unwrap();
    bytes
}

#[test]
fn real_corpus_g1_1_zero_byte_identity_across_src_and_fixtures() {
    let root = repo_root();
    let mut corpus: Vec<String> = Vec::new();

    // Include every real Rust source file in mde's own src/ directory.
    for entry in fs::read_dir(root.join("src")).unwrap().flatten() {
        let p = entry.path();
        if p.extension().and_then(|e| e.to_str()) == Some("rs") {
            let rel = p
                .strip_prefix(&root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            corpus.push(rel);
        }
    }

    // Add all clean multi-language fixtures.
    corpus.extend(
        [
            "tests/fixtures/rust/sample_service.rs",
            "tests/fixtures/rust/macro_module.rs",
            "tests/fixtures/python/ledger_worker.py",
            "tests/fixtures/c/ring_buffer.c",
            "tests/fixtures/c/ifdef_branch.c",
            "tests/fixtures/typescript/api_client.ts",
            "tests/fixtures/typescript/StatusCard.tsx",
            "tests/fixtures/lean/nat_add.lean",
            "tests/fixtures/prose/clean_note.md",
            "tests/fixtures/json/policy_sample.json",
        ]
        .iter()
        .map(|s| (*s).to_string()),
    );
    corpus.sort();
    assert!(corpus.len() >= 17, "expected >= 17 real corpus files");

    for rel in &corpus {
        let bytes = fs::read(root.join(rel)).expect("read corpus file");
        let parsed = analyze_file(rel, &bytes).expect("parse corpus file");
        assert!(
            parsed.error_spans.is_empty(),
            "clean corpus file {rel} had unexpected ERROR spans: {:?}",
            parsed.error_spans
        );
        let roundtripped = apply_byte_span_edits(rel, &bytes, &[]).expect("0-edit roundtrip");
        assert_eq!(
            roundtripped, bytes,
            "G1.1 0-byte identity failed on {rel}"
        );
    }
}

#[test]
fn real_corpus_g1_2_strict_span_splice_across_four_languages() {
    let cases: &[(&str, &str, &str, &str, &str)] = &[
        (
            "tests/fixtures/rust/sample_service.rs",
            "src/sample_service.rs",
            "merge_counts",
            "pub fn merge_counts(a: &BTreeMap<String, u64>, b: &BTreeMap<String, u64>) -> BTreeMap<String, u64> {\n    let mut out = b.clone();\n    for (k, v) in a {\n        *out.entry(k.clone()).or_insert(0) += v;\n    }\n    out\n}",
            "// Sibling comment above consume MUST stay byte-identical.",
        ),
        (
            "tests/fixtures/python/ledger_worker.py",
            "src/ledger_worker.py",
            "compute_score",
            "def compute_score(entries: list[Entry]) -> int:  # type: ignore[misc]\n    \"\"\"Sum positive entry values.\"\"\"\n    return sum(item.value for item in entries if item.value > 0)",
            "# Preserve this sibling comment and trailing comma formatting.",
        ),
        (
            "tests/fixtures/c/ring_buffer.c",
            "src/ring_buffer.c",
            "ring_count",
            "size_t ring_count(const RingBuf *r) {\n    return (size_t)((r->head - r->tail) & 63u);\n}",
            "// Inline comment preserved across edits.",
        ),
        (
            "tests/fixtures/typescript/api_client.ts",
            "src/api_client.ts",
            "formatHeader",
            "function formatHeader(rec: DigestRecord): string {\n  return `${rec.id}=${rec.sha256}`;\n}",
            "// Keep sibling comment intact during function splices.",
        ),
    ];

    for (fixture, dest_rel, symbol_name, replacement, untouched_comment) in cases {
        let tmp = TempDir::new().unwrap();
        let original = copy_fixture_into_temp(tmp.path(), fixture, dest_rel);
        let mut broker = Broker::open(tmp.path(), false).unwrap();

        let loc = broker
            .splice_locate(LocateRequest {
                path: (*dest_rel).to_string(),
                capability_id: None,
            })
            .unwrap();
        let sym = loc
            .symbols
            .iter()
            .find(|s| s.symbol == *symbol_name)
            .unwrap_or_else(|| panic!("symbol {symbol_name} missing in {fixture}"));

        let pkt = broker
            .splice_patch(PatchRequest {
                capability_id: format!("cap.corpus.{symbol_name}"),
                read_tokens: vec![sym.read_token.clone()],
                edits: vec![PatchEditInput {
                    path: (*dest_rel).to_string(),
                    start_byte: sym.start_byte,
                    end_byte: sym.end_byte,
                    expected_old_sha256: sym.span_sha256.clone(),
                    replacement_utf8: (*replacement).to_string(),
                    anchor_symbol: Some((*symbol_name).to_string()),
                    anchor_node_kind: Some(sym.kind.clone()),
                }],
                lane: None,
                seam_contract: None,
                commit_subject: None,
                summary_lines: vec![],
                allow_oracle_write: false,
                actor: None,
                mode: None,
                model_id: None,
            })
            .unwrap();

        let patched = apply_byte_span_edits(dest_rel, &original, &pkt.edits).unwrap();
        assert_eq!(&patched[..sym.start_byte], &original[..sym.start_byte]);
        assert!(patched.ends_with(&original[sym.end_byte..]));
        let patched_str = String::from_utf8(patched).unwrap();
        assert!(
            patched_str.contains(untouched_comment),
            "sibling comment lost in {fixture}"
        );
    }
}

#[test]
fn real_corpus_g1_3_broken_syntax_refusal_across_four_languages() {
    let broken_cases: &[(&str, &str)] = &[
        ("tests/fixtures/rust/broken_syntax.rs", "src/broken.rs"),
        ("tests/fixtures/python/broken_syntax.py", "src/broken.py"),
        ("tests/fixtures/c/broken_syntax.c", "src/broken.c"),
        ("tests/fixtures/typescript/broken_syntax.ts", "src/broken.ts"),
    ];

    for (fixture, dest_rel) in broken_cases {
        let tmp = TempDir::new().unwrap();
        let original = copy_fixture_into_temp(tmp.path(), fixture, dest_rel);
        let mut broker = Broker::open(tmp.path(), false).unwrap();

        let loc = broker
            .splice_locate(LocateRequest {
                path: (*dest_rel).to_string(),
                capability_id: None,
            })
            .unwrap();
        assert!(
            !loc.error_spans.is_empty(),
            "expected ERROR spans in {fixture}"
        );

        let err = broker
            .splice_patch(PatchRequest {
                capability_id: "cap.repair".into(),
                read_tokens: vec![loc.file_read_token],
                edits: vec![PatchEditInput {
                    path: (*dest_rel).to_string(),
                    start_byte: 0,
                    end_byte: original.len(),
                    expected_old_sha256: sha256_prefixed(&original),
                    replacement_utf8: "// replaced\n".into(),
                    anchor_symbol: None,
                    anchor_node_kind: None,
                }],
                lane: None,
                seam_contract: None,
                commit_subject: None,
                summary_lines: vec![],
                allow_oracle_write: false,
                actor: None,
                mode: None,
                model_id: None,
            })
            .unwrap_err();
        assert_eq!(
            err.code, "ERR_SYNTAX_ERROR_REGION",
            "G1.3 failed to refuse broken fixture {fixture}"
        );
    }
}

#[test]
fn real_corpus_g1_4_macro_opacity_refusal_in_c_and_rust() {
    let macro_cases: &[(&str, &str, &str)] = &[
        ("tests/fixtures/c/ifdef_branch.c", "src/ifdef_branch.c", "scale_value"),
        ("tests/fixtures/rust/macro_module.rs", "src/macro_module.rs", "expand_items"),
    ];

    for (fixture, dest_rel, symbol_name) in macro_cases {
        let tmp = TempDir::new().unwrap();
        copy_fixture_into_temp(tmp.path(), fixture, dest_rel);
        let mut broker = Broker::open(tmp.path(), false).unwrap();

        let loc = broker
            .splice_locate(LocateRequest {
                path: (*dest_rel).to_string(),
                capability_id: None,
            })
            .unwrap();
        assert!(
            !loc.macro_opaque_spans.is_empty(),
            "expected macro_opaque_spans in {fixture}"
        );
        let sym = loc
            .symbols
            .iter()
            .find(|s| s.symbol == *symbol_name)
            .expect("symbol present");

        let err = broker
            .splice_patch(PatchRequest {
                capability_id: "cap.macro".into(),
                read_tokens: vec![sym.read_token.clone()],
                edits: vec![PatchEditInput {
                    path: (*dest_rel).to_string(),
                    start_byte: sym.start_byte,
                    end_byte: sym.end_byte,
                    expected_old_sha256: sym.span_sha256.clone(),
                    replacement_utf8: "// edited".into(),
                    anchor_symbol: Some((*symbol_name).to_string()),
                    anchor_node_kind: None,
                }],
                lane: None,
                seam_contract: None,
                commit_subject: None,
                summary_lines: vec![],
                allow_oracle_write: false,
                actor: None,
                mode: None,
                model_id: None,
            })
            .unwrap_err();
        assert_eq!(err.code, "ERR_MACRO_OPAQUE");
    }
}

#[test]
fn zone_manifest_schema_matches_compiled_rules_and_classifies_five_zones() {
    let root = repo_root();
    let schema_path = root.join("schemas/zone-manifest.v0.1.json");
    let verified = verify_zone_manifest_file(&schema_path)
        .expect("schemas/zone-manifest.v0.1.json must match build_zone_manifest()");
    let fresh = build_zone_manifest().unwrap();
    assert_eq!(verified, fresh);
    assert_eq!(
        verified.precedence_order,
        vec![
            Zone::FormalProof,
            Zone::CondensedJson,
            Zone::UiModule,
            Zone::Code,
            Zone::Prose,
        ]
    );

    // Confirm all 5 canonical zones classify accurately on fixtures.
    let tmp = TempDir::new().unwrap();
    let expected: &[(&str, &str, Zone)] = &[
        ("tests/fixtures/prose/clean_note.md", "docs/note.md", Zone::Prose),
        ("tests/fixtures/rust/sample_service.rs", "src/svc.rs", Zone::Code),
        ("tests/fixtures/lean/nat_add.lean", "proofs/nat.lean", Zone::FormalProof),
        ("tests/fixtures/typescript/StatusCard.tsx", "ui/Card.tsx", Zone::UiModule),
        ("tests/fixtures/json/policy_sample.json", "cfg/policy.json", Zone::CondensedJson),
    ];

    let mut broker = Broker::open(tmp.path(), false).unwrap();
    for (fixture, dest_rel, want_zone) in expected {
        copy_fixture_into_temp(tmp.path(), fixture, dest_rel);
        let loc = broker
            .splice_locate(LocateRequest {
                path: (*dest_rel).to_string(),
                capability_id: None,
            })
            .unwrap();
        assert_eq!(loc.dominant_zone, *want_zone, "zone mismatch on {fixture}");
        assert_eq!(loc.meta[MDE_META_NAMESPACE].zone_hint, *want_zone);
    }
}

#[test]
fn native_rust_guard_checks_all_rules_and_blocks_dirty_prose_splice() {
    let root = repo_root();
    let opts = GuardOptions {
        check_mentions: true,
        ..Default::default()
    };

    // 1. All mde repository docs must pass native mde guard cleanly.
    let repo_docs = vec![
        root.join("README.md").to_string_lossy().into_owned(),
        root.join("PROTOCOL.md").to_string_lossy().into_owned(),
        root.join("PLAN.md").to_string_lossy().into_owned(),
    ];
    let clean_report = check_files(&repo_docs, &opts).unwrap();
    assert!(
        clean_report.passed,
        "repo docs failed native mde guard: {:?}",
        clean_report.findings
    );

    // 2. Adversarial inputs must trigger every deterministic guard rule.
    let long_para = "word ".repeat(90); // > 420 chars
    let fake_home = concat!("/", "Users", "/alice/notes.md");
    let fake_key = concat!("AKIA", "0123456789ABCDEF");
    let dirty_doc = format!(
        "Notably, this is the right shape \u{2014} see https://github.com/org/repo/issues/42.\n\
         This long sentence uses a clause semicolon to stitch two ideas together; it should split.\n\
         Once this ships, issue #42 should be closed by @selfping.\n\
         {long_para}\n\
         Leaked path {fake_home} and key {fake_key}.\n"
    );
    let dirty_report = check_sources(&[("dirty.md", &dirty_doc)], &opts);
    assert!(!dirty_report.passed);
    let rules: Vec<&str> = dirty_report
        .findings
        .iter()
        .map(|f| f.rule.as_str())
        .collect();
    for required in [
        "em_dash",
        "clause_semicolon",
        "long_paragraph",
        "ai_tell",
        "outcome_forecast",
        "duplicate_reference",
        "mention_candidate",
        "secret_or_path_leak",
    ] {
        assert!(
            rules.contains(&required),
            "guard missed rule '{required}'; got: {rules:?}"
        );
    }

    // 3. Call-policy guard blocks disallowed verb and protected oracle write.
    let policy = PolicyConfig::default();
    let bad_verb = evaluate_call_policy(
        &root,
        &CallPolicyRequest {
            verb: "raw_shell_exec".into(),
            paths: vec!["README.md".into()],
            eval_count: 1,
            allow_oracle_write: false,
        },
        &policy,
    );
    assert!(!bad_verb.allowed);
    assert_eq!(bad_verb.rejection.unwrap().code, "ERR_POLICY_DENIED");

    let bad_oracle = evaluate_call_policy(
        &root,
        &CallPolicyRequest {
            verb: "splice_patch".into(),
            paths: vec!["tests/conformance.rs".into()],
            eval_count: 1,
            allow_oracle_write: false,
        },
        &policy,
    );
    assert!(!bad_oracle.allowed);
    assert_eq!(bad_oracle.rejection.unwrap().code, "ERR_PROTECTED_ORACLE");

    // 4. End-to-end splice_verify automatically fails when a patched Zone::Prose doc has an em dash.
    let tmp = TempDir::new().unwrap();
    let orig = copy_fixture_into_temp(tmp.path(), "tests/fixtures/prose/clean_note.md", "docs/note.md");
    let mut broker = Broker::open(tmp.path(), false).unwrap();
    let loc = broker
        .splice_locate(LocateRequest {
            path: "docs/note.md".into(),
            capability_id: None,
        })
        .unwrap();
    let pkt = broker
        .splice_patch(PatchRequest {
            capability_id: "cap.docs.note".into(),
            read_tokens: vec![loc.file_read_token],
            edits: vec![PatchEditInput {
                path: "docs/note.md".into(),
                start_byte: 0,
                end_byte: orig.len(),
                expected_old_sha256: sha256_prefixed(&orig),
                replacement_utf8: "# Note\n\nNotably, this edit adds an em dash \u{2014} and once this ships it fails.\n".into(),
                anchor_symbol: None,
                anchor_node_kind: None,
            }],
            lane: None,
            seam_contract: None,
            commit_subject: None,
            summary_lines: vec![],
            allow_oracle_write: false,
            actor: None,
            mode: None,
            model_id: None,
        })
        .unwrap();

    let bundle = broker
        .splice_verify(VerifyRequest {
            packet_id: pkt.packet_id,
            eval_count: None,
        })
        .unwrap();
    assert_eq!(bundle.summary.lexicase_grade, "rejected");
    assert!(
        bundle
            .anchors
            .iter()
            .any(|a| a.anchor_id == "mde_prose_guard:docs/note.md" && !a.passed),
        "expected failing mde_prose_guard anchor on dirty prose splice"
    );

    // 5. CLI `mde guard` returns exit 0 on clean doc and exit 1 on dirty text.
    let bin = env!("CARGO_BIN_EXE_mde");
    let ok_cli = Command::new(bin)
        .args(["guard", root.join("README.md").to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(ok_cli.status.success());
    let ok_json: Value = serde_json::from_slice(&ok_cli.stdout).unwrap();
    assert_eq!(ok_json["passed"], true);

    let fail_cli = Command::new(bin)
        .args([
            "guard",
            "--text",
            "Notably, once this ships it will fail \u{2014} yes.",
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(fail_cli.status.code(), Some(1));
    let fail_json: Value = serde_json::from_slice(&fail_cli.stdout).unwrap();
    assert_eq!(fail_json["passed"], false);

    // 6. Broker `mde_guard` method works cleanly.
    let guard_val = broker
        .mde_guard(GuardRequest {
            paths: vec!["docs/note.md".into()],
            text: None,
            check_dupes: Some(true),
            check_mentions: false,
            call_policy: None,
        })
        .unwrap();
    assert_eq!(guard_val["passed"], true);
}
