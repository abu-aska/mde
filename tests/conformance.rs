use mde::broker::{
    Broker, LocateRequest, PatchEditInput, PatchRequest, ProjectRequest, TraceRequest,
    VerifyRequest,
};
use mde::cst::apply_byte_span_edits;
use mde::policy::{confine_path, AnchorSpec, PolicyConfig};
use mde::types::{sha256_prefixed, RiskClass, Zone, MDE_META_NAMESPACE};
use serde_json::{json, Value};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use tempfile::TempDir;

fn init_git_repo(dir: &Path) {
    let run = |args: &[&str]| {
        let out = Command::new("git")
            .current_dir(dir)
            .args(args)
            .output()
            .expect("git exec");
        assert!(
            out.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
    };
    run(&["init", "-b", "main"]);
    run(&["config", "user.name", "mde-test"]);
    run(&["config", "user.email", "mde-test@example.invalid"]);
}

fn commit_all(dir: &Path, msg: &str) {
    let run = |args: &[&str]| {
        let out = Command::new("git")
            .current_dir(dir)
            .args(args)
            .output()
            .expect("git exec");
        assert!(
            out.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
    };
    run(&["add", "."]);
    run(&["commit", "-m", msg]);
}

#[test]
fn g1_1_zero_byte_identity_roundtrip_across_languages() {
    let samples: &[(&str, &[u8])] = &[
        (
            "src/sample.rs",
            b"//! Module doc\n\n#[allow(dead_code)]\n// keep comment\npub fn add(a: i32, b: i32) -> i32 {\n    a + b // trailing\n}\n",
        ),
        (
            "src/sample.py",
            b"# top pragma: no cover\n\ndef greet(name: str) -> str:  # type: ignore\n    \"\"\"Docstring preserved.\"\"\"\n    return f\"hi {name}\"\n\n",
        ),
        (
            "src/sample.c",
            b"/* header comment */\n#include <stdint.h>\n\nint sum(int a, int b) {\n    return a + b; /* inline */\n}\n",
        ),
        (
            "src/sample.ts",
            b"// eslint-disable-next-line\nexport function mul(a: number, b: number): number {\n  return a * b;\n}\n",
        ),
    ];

    for (path, bytes) in samples {
        let out = apply_byte_span_edits(path, bytes, &[]).expect("zero-edit roundtrip");
        assert_eq!(out.as_slice(), *bytes, "zero-byte identity violated on {path}");
    }
}

#[test]
fn g1_2_strict_byte_span_diff_preserves_sibling_comments_and_pragmas() {
    let tmp = TempDir::new().unwrap();
    let src_dir = tmp.path().join("src");
    fs::create_dir_all(&src_dir).unwrap();
    let original = concat!(
        "// Leading header comment\n",
        "#[allow(dead_code)]\n",
        "pub fn alpha(x: i32) -> i32 {\n",
        "    x + 1\n",
        "}\n\n",
        "/* Sibling comment MUST stay untouched */\n",
        "#[allow(unused_variables)]\n",
        "pub fn beta(y: i32) -> i32 {\n",
        "    y * 2\n",
        "}\n"
    );
    fs::write(src_dir.join("lib.rs"), original).unwrap();

    let mut broker = Broker::open(tmp.path(), false).unwrap();
    let loc = broker
        .splice_locate(LocateRequest {
            path: "src/lib.rs".into(),
            capability_id: None,
        })
        .unwrap();

    let alpha = loc.symbols.iter().find(|s| s.symbol == "alpha").unwrap();
    let replacement = "pub fn alpha(x: i32) -> i32 {\n    x + 10\n}";
    let packet = broker
        .splice_patch(PatchRequest {
            capability_id: "cap.math.alpha".into(),
            read_tokens: vec![alpha.read_token.clone()],
            edits: vec![PatchEditInput {
                path: "src/lib.rs".into(),
                start_byte: alpha.start_byte,
                end_byte: alpha.end_byte,
                expected_old_sha256: alpha.span_sha256.clone(),
                replacement_utf8: replacement.into(),
                anchor_symbol: Some("alpha".into()),
                anchor_node_kind: Some(alpha.kind.clone()),
            }],
            lane: None,
            seam_contract: None,
            commit_subject: Some("math: bump alpha offset".into()),
            summary_lines: vec![],
            allow_oracle_write: false,
            actor: None,
            mode: None,
            model_id: None,
        })
        .unwrap();

    let patched = apply_byte_span_edits("src/lib.rs", original.as_bytes(), &packet.edits).unwrap();
    let patched_str = String::from_utf8(patched).unwrap();

    assert!(patched_str.starts_with("// Leading header comment\n#[allow(dead_code)]\n"));
    assert!(patched_str.contains("/* Sibling comment MUST stay untouched */\n#[allow(unused_variables)]\npub fn beta(y: i32) -> i32 {\n    y * 2\n}\n"));
    assert!(patched_str.contains("x + 10"));
    assert_eq!(&patched_str[..alpha.start_byte], &original[..alpha.start_byte]);
    let orig_tail = &original[alpha.end_byte..];
    assert!(patched_str.ends_with(orig_tail));
}

#[test]
fn g1_3_refuse_broken_syntax_and_syntax_breaking_patches() {
    let tmp = TempDir::new().unwrap();
    fs::create_dir_all(tmp.path().join("src")).unwrap();
    let broken_rs = "pub fn broken( { let x = ; }\n";
    fs::write(tmp.path().join("src/broken.rs"), broken_rs).unwrap();

    let mut broker = Broker::open(tmp.path(), false).unwrap();
    let loc = broker
        .splice_locate(LocateRequest {
            path: "src/broken.rs".into(),
            capability_id: None,
        })
        .unwrap();
    assert!(!loc.error_spans.is_empty(), "expected tree-sitter ERROR spans");

    let err = broker
        .splice_patch(PatchRequest {
            capability_id: "cap.broken".into(),
            read_tokens: vec![loc.file_read_token.clone()],
            edits: vec![PatchEditInput {
                path: "src/broken.rs".into(),
                start_byte: 0,
                end_byte: broken_rs.len(),
                expected_old_sha256: sha256_prefixed(broken_rs.as_bytes()),
                replacement_utf8: "pub fn fixed() {}\n".into(),
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
    assert_eq!(err.code, "ERR_SYNTAX_ERROR_REGION");
    assert!(err.detail.is_some());

    // Also verify a patch that introduces new syntax errors on a clean file is rejected.
    let clean_py = "def ok(x):\n    return x + 1\n";
    fs::write(tmp.path().join("src/ok.py"), clean_py).unwrap();
    let loc2 = broker
        .splice_locate(LocateRequest {
            path: "src/ok.py".into(),
            capability_id: None,
        })
        .unwrap();
    let sym = &loc2.symbols[0];
    let err2 = broker
        .splice_patch(PatchRequest {
            capability_id: "cap.bad_edit".into(),
            read_tokens: vec![sym.read_token.clone()],
            edits: vec![PatchEditInput {
                path: "src/ok.py".into(),
                start_byte: sym.start_byte,
                end_byte: sym.end_byte,
                expected_old_sha256: sym.span_sha256.clone(),
                replacement_utf8: "def ok(x:\n    return ((".into(),
                anchor_symbol: Some("ok".into()),
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
    assert_eq!(err2.code, "ERR_PATCH_INTRODUCED_SYNTAX_ERROR");
}

#[test]
fn g1_4_refuse_macro_opaque_regions_in_c_and_rust() {
    let tmp = TempDir::new().unwrap();
    fs::create_dir_all(tmp.path().join("src")).unwrap();

    let c_code = "#ifdef FEATURE_FAST\nint fast(int x) { return x * 2; }\n#endif\n";
    fs::write(tmp.path().join("src/feat.c"), c_code).unwrap();

    let mut broker = Broker::open(tmp.path(), false).unwrap();
    let loc_c = broker
        .splice_locate(LocateRequest {
            path: "src/feat.c".into(),
            capability_id: None,
        })
        .unwrap();
    assert!(!loc_c.macro_opaque_spans.is_empty());
    let fast = loc_c.symbols.iter().find(|s| s.symbol == "fast").unwrap();

    let err_c = broker
        .splice_patch(PatchRequest {
            capability_id: "cap.c_macro".into(),
            read_tokens: vec![fast.read_token.clone()],
            edits: vec![PatchEditInput {
                path: "src/feat.c".into(),
                start_byte: fast.start_byte,
                end_byte: fast.end_byte,
                expected_old_sha256: fast.span_sha256.clone(),
                replacement_utf8: "int fast(int x) { return x * 4; }".into(),
                anchor_symbol: Some("fast".into()),
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
    assert_eq!(err_c.code, "ERR_MACRO_OPAQUE");

    let rs_code = "macro_rules! make_val { () => { 42 }; }\npub fn get() -> i32 { make_val!() }\n";
    fs::write(tmp.path().join("src/mac.rs"), rs_code).unwrap();
    let loc_rs = broker
        .splice_locate(LocateRequest {
            path: "src/mac.rs".into(),
            capability_id: None,
        })
        .unwrap();
    assert!(!loc_rs.macro_opaque_spans.is_empty());
    let get_fn = loc_rs.symbols.iter().find(|s| s.symbol == "get").unwrap();

    let err_rs = broker
        .splice_patch(PatchRequest {
            capability_id: "cap.rs_macro".into(),
            read_tokens: vec![get_fn.read_token.clone()],
            edits: vec![PatchEditInput {
                path: "src/mac.rs".into(),
                start_byte: get_fn.start_byte,
                end_byte: get_fn.end_byte,
                expected_old_sha256: get_fn.span_sha256.clone(),
                replacement_utf8: "pub fn get() -> i32 { 7 }".into(),
                anchor_symbol: Some("get".into()),
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
    assert_eq!(err_rs.code, "ERR_MACRO_OPAQUE");
}

#[test]
fn read_before_write_lock_rejects_unread_and_stale_tokens() {
    let tmp = TempDir::new().unwrap();
    fs::create_dir_all(tmp.path().join("src")).unwrap();
    let src = "def add(a, b):\n    return a + b\n";
    let file_path = tmp.path().join("src/calc.py");
    fs::write(&file_path, src).unwrap();

    let mut broker = Broker::open(tmp.path(), false).unwrap();

    // 1. Unread edit must fail with ERR_READ_REQUIRED.
    let err = broker
        .splice_patch(PatchRequest {
            capability_id: "cap.calc".into(),
            read_tokens: vec!["forged-token".into()],
            edits: vec![PatchEditInput {
                path: "src/calc.py".into(),
                start_byte: 0,
                end_byte: src.len(),
                expected_old_sha256: sha256_prefixed(src.as_bytes()),
                replacement_utf8: "def add(a, b):\n    return a + b + 1\n".into(),
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
    assert_eq!(err.code, "ERR_READ_REQUIRED");

    // 2. Stale read_token after external disk modification must fail.
    let loc = broker
        .splice_locate(LocateRequest {
            path: "src/calc.py".into(),
            capability_id: None,
        })
        .unwrap();
    fs::write(&file_path, "def add(a, b):\n    return a + b + 99\n").unwrap();
    let err_stale = broker
        .splice_patch(PatchRequest {
            capability_id: "cap.calc".into(),
            read_tokens: vec![loc.file_read_token],
            edits: vec![PatchEditInput {
                path: "src/calc.py".into(),
                start_byte: 0,
                end_byte: src.len(),
                expected_old_sha256: sha256_prefixed(src.as_bytes()),
                replacement_utf8: "def add(a, b):\n    return a + b + 1\n".into(),
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
    assert_eq!(err_stale.code, "ERR_READ_REQUIRED");
}

#[test]
fn g3_4_protected_oracle_refusal_path_confinement_and_tamper_check() {
    let tmp = TempDir::new().unwrap();
    init_git_repo(tmp.path());
    fs::create_dir_all(tmp.path().join("src")).unwrap();
    fs::create_dir_all(tmp.path().join("tests")).unwrap();
    fs::create_dir_all(tmp.path().join(".mde")).unwrap();

    fs::write(tmp.path().join("src/app.py"), "def val():\n    return 1\n").unwrap();
    fs::write(
        tmp.path().join("tests/test_app.py"),
        "def test_ok():\n    assert True\n",
    )
    .unwrap();

    // Path confinement rejections.
    assert_eq!(
        confine_path(tmp.path(), "../escape.py").unwrap_err().code,
        "ERR_PATH_OUT_OF_BOUNDS"
    );
    assert_eq!(
        confine_path(tmp.path(), "/etc/passwd").unwrap_err().code,
        "ERR_PATH_OUT_OF_BOUNDS"
    );
    assert_eq!(
        confine_path(tmp.path(), ".git/config").unwrap_err().code,
        "ERR_PATH_OUT_OF_BOUNDS"
    );

    let mut broker = Broker::open(tmp.path(), false).unwrap();
    let loc_test = broker
        .splice_locate(LocateRequest {
            path: "tests/test_app.py".into(),
            capability_id: None,
        })
        .unwrap();

    // Direct write to protected oracle path fails closed.
    let err = broker
        .splice_patch(PatchRequest {
            capability_id: "cap.app".into(),
            read_tokens: vec![loc_test.file_read_token],
            edits: vec![PatchEditInput {
                path: "tests/test_app.py".into(),
                start_byte: 0,
                end_byte: loc_test.total_bytes,
                expected_old_sha256: loc_test.blob_sha256,
                replacement_utf8: "def test_ok():\n    assert False\n".into(),
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
    assert_eq!(err.code, "ERR_PROTECTED_ORACLE");

    // Configure an anchor that illegally mutates tests/test_app.py during verification.
    let mut policy = PolicyConfig::default();
    policy.anchors.push(AnchorSpec {
        anchor_id: "tampering_anchor".into(),
        tier: 1,
        visibility: "visible".into(),
        zone: "A".into(),
        cmd: vec![
            "sh".into(),
            "-c".into(),
            "echo '# tampered' >> tests/test_app.py".into(),
        ],
        path_prefixes: vec!["src/".into()],
        cassette_sha256: None,
    });
    fs::write(
        tmp.path().join(".mde/policy.json"),
        serde_json::to_vec_pretty(&policy).unwrap(),
    )
    .unwrap();
    commit_all(tmp.path(), "init");

    let loc_app = broker
        .splice_locate(LocateRequest {
            path: "src/app.py".into(),
            capability_id: None,
        })
        .unwrap();
    let sym = &loc_app.symbols[0];
    let packet = broker
        .splice_patch(PatchRequest {
            capability_id: "cap.app".into(),
            read_tokens: vec![sym.read_token.clone()],
            edits: vec![PatchEditInput {
                path: "src/app.py".into(),
                start_byte: sym.start_byte,
                end_byte: sym.end_byte,
                expected_old_sha256: sym.span_sha256.clone(),
                replacement_utf8: "def val():\n    return 2".into(),
                anchor_symbol: Some("val".into()),
                anchor_node_kind: None,
            }],
            lane: None,
            seam_contract: None,
            commit_subject: Some("app: return 2".into()),
            summary_lines: vec![],
            allow_oracle_write: false,
            actor: None,
            mode: None,
            model_id: None,
        })
        .unwrap();

    let bundle = broker
        .splice_verify(VerifyRequest {
            packet_id: packet.packet_id.clone(),
            eval_count: None,
        })
        .unwrap();
    assert!(!bundle.oracle_integrity.tamper_free);
    assert_eq!(bundle.summary.lexicase_grade, "rejected");

    // Projecting a tampered bundle must be blocked.
    let proj_err = broker
        .splice_project(ProjectRequest {
            packet_id: packet.packet_id,
            bundle_id: bundle.bundle_id,
            approve_diff_sha256: None,
        })
        .unwrap_err();
    assert_eq!(proj_err.code, "ERR_VERIFY_FAILED");
}

#[test]
fn zone_classifier_and_dynamic_site_widening() {
    let tmp = TempDir::new().unwrap();
    fs::create_dir_all(tmp.path().join("src")).unwrap();
    fs::create_dir_all(tmp.path().join("proofs")).unwrap();
    fs::create_dir_all(tmp.path().join("docs")).unwrap();
    fs::create_dir_all(tmp.path().join(".mde")).unwrap();

    fs::write(tmp.path().join("docs/guide.md"), "# Guide\n\nPlain prose.\n").unwrap();
    fs::write(
        tmp.path().join("proofs/add.lean"),
        "theorem add_zero (n : Nat) : n + 0 = n := by rfl\n",
    )
    .unwrap();
    fs::write(
        tmp.path().join("src/Button.tsx"),
        "export function Button() {\n  return <button className=\"btn\">Go</button>;\n}\n",
    )
    .unwrap();
    fs::write(
        tmp.path().join("src/dyn.py"),
        "def dispatch(obj, name):\n    return getattr(obj, name)()\n",
    )
    .unwrap();

    let mut policy = PolicyConfig::default();
    policy.anchors.push(AnchorSpec {
        anchor_id: "direct_dyn".into(),
        tier: 1,
        visibility: "visible".into(),
        zone: "A".into(),
        cmd: vec!["true".into()],
        path_prefixes: vec!["src/dyn.py".into()],
        cassette_sha256: None,
    });
    policy.anchors.push(AnchorSpec {
        anchor_id: "other_module_anchor".into(),
        tier: 1,
        visibility: "visible".into(),
        zone: "A".into(),
        cmd: vec!["true".into()],
        path_prefixes: vec!["other/".into()],
        cassette_sha256: None,
    });
    fs::write(
        tmp.path().join(".mde/policy.json"),
        serde_json::to_vec_pretty(&policy).unwrap(),
    )
    .unwrap();

    let mut broker = Broker::open(tmp.path(), false).unwrap();

    let loc_prose = broker
        .splice_locate(LocateRequest {
            path: "docs/guide.md".into(),
            capability_id: None,
        })
        .unwrap();
    assert_eq!(loc_prose.dominant_zone, Zone::Prose);
    assert_eq!(loc_prose.meta[MDE_META_NAMESPACE].zone_hint, Zone::Prose);

    let loc_proof = broker
        .splice_locate(LocateRequest {
            path: "proofs/add.lean".into(),
            capability_id: None,
        })
        .unwrap();
    assert_eq!(loc_proof.dominant_zone, Zone::FormalProof);
    assert_eq!(loc_proof.meta[MDE_META_NAMESPACE].zone_hint, Zone::FormalProof);

    let loc_ui = broker
        .splice_locate(LocateRequest {
            path: "src/Button.tsx".into(),
            capability_id: None,
        })
        .unwrap();
    assert_eq!(loc_ui.dominant_zone, Zone::UiModule);
    assert_eq!(loc_ui.symbols[0].zone, Zone::UiModule);

    let trace = broker
        .splice_trace(TraceRequest {
            path: "src/dyn.py".into(),
            symbol: Some("dispatch".into()),
        })
        .unwrap();
    assert_eq!(trace.dominant_zone, Zone::Code);
    assert!(
        trace
            .unresolved_dynamic_sites
            .iter()
            .any(|s| s.kind == "python_dynamic_getattr"),
        "expected getattr dynamic site"
    );
    assert!(trace.mapped_anchors.contains(&"direct_dyn".to_string()));
    assert!(
        trace.widened_anchors.contains(&"other_module_anchor".to_string()),
        "unresolved dynamic site must widen anchor scope"
    );
}

#[test]
fn g4_1_g4_3_and_g7_3_git_projection_plain_git_reingest_and_high_risk_approval() {
    let tmp = TempDir::new().unwrap();
    init_git_repo(tmp.path());
    fs::create_dir_all(tmp.path().join("src")).unwrap();
    fs::create_dir_all(tmp.path().join("auth")).unwrap();
    fs::write(
        tmp.path().join("src/math.rs"),
        "// Keep me\npub fn double(x: i32) -> i32 {\n    x + x\n}\n",
    )
    .unwrap();
    fs::write(
        tmp.path().join("auth/check.py"),
        "def verify(tok):\n    return tok == 'ok'\n",
    )
    .unwrap();
    commit_all(tmp.path(), "initial commit");

    let mut broker = Broker::open(tmp.path(), false).unwrap();

    // Routine splice: locate -> patch -> verify -> project.
    let loc = broker
        .splice_locate(LocateRequest {
            path: "src/math.rs".into(),
            capability_id: None,
        })
        .unwrap();
    let dbl = loc.symbols.iter().find(|s| s.symbol == "double").unwrap();
    let packet = broker
        .splice_patch(PatchRequest {
            capability_id: "cap.math.double".into(),
            read_tokens: vec![dbl.read_token.clone()],
            edits: vec![PatchEditInput {
                path: "src/math.rs".into(),
                start_byte: dbl.start_byte,
                end_byte: dbl.end_byte,
                expected_old_sha256: dbl.span_sha256.clone(),
                replacement_utf8: "pub fn double(x: i32) -> i32 {\n    x * 2\n}".into(),
                anchor_symbol: Some("double".into()),
                anchor_node_kind: Some(dbl.kind.clone()),
            }],
            lane: None,
            seam_contract: None,
            commit_subject: Some("math: multiply by 2".into()),
            summary_lines: vec!["Replaces addition with multiplication.".into()],
            allow_oracle_write: false,
            actor: None,
            mode: None,
            model_id: None,
        })
        .unwrap();
    assert_eq!(packet.risk_class, RiskClass::Routine);

    let bundle = broker
        .splice_verify(VerifyRequest {
            packet_id: packet.packet_id.clone(),
            eval_count: None,
        })
        .unwrap();
    assert_eq!(bundle.summary.lexicase_grade, "canonical");

    let proj = broker
        .splice_project(ProjectRequest {
            packet_id: packet.packet_id.clone(),
            bundle_id: bundle.bundle_id.clone(),
            approve_diff_sha256: None,
        })
        .unwrap();
    assert!(!proj.commit_sha.is_empty());

    let log_out = Command::new("git")
        .current_dir(tmp.path())
        .args(["log", "-1", "--pretty=%B"])
        .output()
        .unwrap();
    let log_msg = String::from_utf8_lossy(&log_out.stdout);
    assert!(log_msg.contains("Splice-Packet:"));
    assert!(log_msg.contains("Splice-Bundle:"));
    assert!(!log_msg.contains("Co-authored-by"));

    // Gate G4.3: Plain Git edit outside mde re-ingests cleanly.
    fs::write(
        tmp.path().join("src/math.rs"),
        "// Keep me\npub fn double(x: i32) -> i32 {\n    x * 2\n}\npub fn triple(x: i32) -> i32 {\n    x * 3\n}\n",
    )
    .unwrap();
    commit_all(tmp.path(), "human plain-git edit");
    let loc_after = broker
        .splice_locate(LocateRequest {
            path: "src/math.rs".into(),
            capability_id: None,
        })
        .unwrap();
    assert!(loc_after.symbols.iter().any(|s| s.symbol == "triple"));

    // Gate G7.3: High-risk path requires exact diff SHA-256 human approval.
    let loc_auth = broker
        .splice_locate(LocateRequest {
            path: "auth/check.py".into(),
            capability_id: None,
        })
        .unwrap();
    let vfn = &loc_auth.symbols[0];
    let auth_pkt = broker
        .splice_patch(PatchRequest {
            capability_id: "cap.auth.verify".into(),
            read_tokens: vec![vfn.read_token.clone()],
            edits: vec![PatchEditInput {
                path: "auth/check.py".into(),
                start_byte: vfn.start_byte,
                end_byte: vfn.end_byte,
                expected_old_sha256: vfn.span_sha256.clone(),
                replacement_utf8: "def verify(tok):\n    return tok == 'strict'".into(),
                anchor_symbol: Some("verify".into()),
                anchor_node_kind: None,
            }],
            lane: None,
            seam_contract: None,
            commit_subject: Some("auth: tighten token check".into()),
            summary_lines: vec![],
            allow_oracle_write: false,
            actor: None,
            mode: None,
            model_id: None,
        })
        .unwrap();
    assert_eq!(auth_pkt.risk_class, RiskClass::HighRisk);

    let auth_bundle = broker
        .splice_verify(VerifyRequest {
            packet_id: auth_pkt.packet_id.clone(),
            eval_count: None,
        })
        .unwrap();
    assert!(auth_bundle.human_approval.required);

    let block_err = broker
        .splice_project(ProjectRequest {
            packet_id: auth_pkt.packet_id.clone(),
            bundle_id: auth_bundle.bundle_id.clone(),
            approve_diff_sha256: None,
        })
        .unwrap_err();
    assert_eq!(block_err.code, "ERR_APPROVAL_REQUIRED");
    let required_sha = block_err.detail.unwrap()["required_diff_sha256"]
        .as_str()
        .unwrap()
        .to_string();

    // Working tree must have been rolled back cleanly after refusal.
    let unchanged = fs::read_to_string(tmp.path().join("auth/check.py")).unwrap();
    assert!(unchanged.contains("'ok'"));

    // Providing exact diff SHA-256 unlocks commit projection.
    let approved_proj = broker
        .splice_project(ProjectRequest {
            packet_id: auth_pkt.packet_id,
            bundle_id: auth_bundle.bundle_id,
            approve_diff_sha256: Some(required_sha),
        })
        .unwrap();
    assert!(!approved_proj.commit_sha.is_empty());
}

#[test]
fn g6_4_secret_and_local_path_scrub_fails_closed() {
    let tmp = TempDir::new().unwrap();
    fs::create_dir_all(tmp.path().join("src")).unwrap();
    fs::create_dir_all(tmp.path().join(".mde")).unwrap();
    fs::write(tmp.path().join("src/cfg.py"), "def cfg():\n    return 'x'\n").unwrap();

    let mut broker = Broker::open(tmp.path(), false).unwrap();
    let loc = broker
        .splice_locate(LocateRequest {
            path: "src/cfg.py".into(),
            capability_id: None,
        })
        .unwrap();
    let sym = &loc.symbols[0];

    let synthetic_home = concat!("/", "Users", "/alice/private.pem");
    let err_path = broker
        .splice_patch(PatchRequest {
            capability_id: "cap.cfg".into(),
            read_tokens: vec![sym.read_token.clone()],
            edits: vec![PatchEditInput {
                path: "src/cfg.py".into(),
                start_byte: sym.start_byte,
                end_byte: sym.end_byte,
                expected_old_sha256: sym.span_sha256.clone(),
                replacement_utf8: format!("def cfg():\n    return '{synthetic_home}'"),
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
    assert_eq!(err_path.code, "ERR_SECRET_OR_PATH_LEAK");

    // Also verify secret printed during splice_verify fails closed.
    let synthetic_key = concat!("AKIA", "0123456789ABCDEF");
    let mut policy = PolicyConfig::default();
    policy.anchors.push(AnchorSpec {
        anchor_id: "leaky_anchor".into(),
        tier: 1,
        visibility: "visible".into(),
        zone: "A".into(),
        cmd: vec!["sh".into(), "-c".into(), format!("echo {synthetic_key}")],
        path_prefixes: vec!["src/".into()],
        cassette_sha256: None,
    });
    fs::write(
        tmp.path().join(".mde/policy.json"),
        serde_json::to_vec_pretty(&policy).unwrap(),
    )
    .unwrap();

    let clean_pkt = broker
        .splice_patch(PatchRequest {
            capability_id: "cap.cfg".into(),
            read_tokens: vec![sym.read_token.clone()],
            edits: vec![PatchEditInput {
                path: "src/cfg.py".into(),
                start_byte: sym.start_byte,
                end_byte: sym.end_byte,
                expected_old_sha256: sym.span_sha256.clone(),
                replacement_utf8: "def cfg():\n    return 'safe'".into(),
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

    let err_verify = broker
        .splice_verify(VerifyRequest {
            packet_id: clean_pkt.packet_id,
            eval_count: None,
        })
        .unwrap_err();
    assert_eq!(err_verify.code, "ERR_SECRET_OR_PATH_LEAK");
}

#[test]
fn live_jsonrpc_stdio_mcp_roundtrip_end_to_end() {
    let tmp = TempDir::new().unwrap();
    init_git_repo(tmp.path());
    fs::create_dir_all(tmp.path().join("src")).unwrap();
    fs::write(
        tmp.path().join("src/hello.ts"),
        "// Keep banner\nexport function greet(): string {\n  return \"hi\";\n}\n",
    )
    .unwrap();
    commit_all(tmp.path(), "seed hello.ts");

    let bin = env!("CARGO_BIN_EXE_mde");
    let mut child = Command::new(bin)
        .args(["--root", tmp.path().to_str().unwrap(), "mcp"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn mde mcp");

    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    let mut rpc = |msg: Value| -> Value {
        writeln!(stdin, "{}", serde_json::to_string(&msg).unwrap()).unwrap();
        stdin.flush().unwrap();
        let mut line = String::new();
        stdout.read_line(&mut line).unwrap();
        serde_json::from_str(&line).expect("valid jsonrpc response")
    };

    // 1. initialize
    let init = rpc(json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}
    }));
    assert_eq!(init["result"]["serverInfo"]["name"], "mde");
    assert_eq!(
        init["result"]["_meta"][MDE_META_NAMESPACE]["read_before_write_lock"],
        true
    );

    // 2. tools/list
    let tools = rpc(json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}
    }));
    let names: Vec<&str> = tools["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        vec![
            "splice_locate",
            "splice_trace",
            "splice_patch",
            "splice_verify",
            "splice_project"
        ]
    );

    // 3. splice_locate
    let loc = rpc(json!({
        "jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "params": {"name": "splice_locate", "arguments": {"path": "src/hello.ts"}}
    }));
    assert_eq!(loc["result"]["isError"], false);
    assert_eq!(loc["result"]["_meta"][MDE_META_NAMESPACE]["zone_hint"], "code");
    let greet = &loc["result"]["structuredContent"]["symbols"][0];
    let tok = greet["read_token"].as_str().unwrap().to_string();
    let start = greet["start_byte"].as_u64().unwrap();
    let end = greet["end_byte"].as_u64().unwrap();
    let old_sha = greet["span_sha256"].as_str().unwrap().to_string();

    // 4. splice_patch WITHOUT valid token fails closed
    let bad_patch = rpc(json!({
        "jsonrpc": "2.0", "id": 4, "method": "tools/call",
        "params": {
            "name": "splice_patch",
            "arguments": {
                "capability_id": "cap.greet",
                "read_tokens": ["bad"],
                "edits": [{
                    "path": "src/hello.ts",
                    "start_byte": start,
                    "end_byte": end,
                    "expected_old_sha256": old_sha,
                    "replacement_utf8": "function greet(): string {\n  return \"hello\";\n}"
                }]
            }
        }
    }));
    assert_eq!(bad_patch["result"]["isError"], true);
    assert_eq!(
        bad_patch["result"]["structuredContent"]["code"],
        "ERR_READ_REQUIRED"
    );

    // 5. splice_patch WITH valid token succeeds
    let ok_patch = rpc(json!({
        "jsonrpc": "2.0", "id": 5, "method": "tools/call",
        "params": {
            "name": "splice_patch",
            "arguments": {
                "capability_id": "cap.greet",
                "read_tokens": [tok],
                "commit_subject": "greet: return hello",
                "edits": [{
                    "path": "src/hello.ts",
                    "start_byte": start,
                    "end_byte": end,
                    "expected_old_sha256": old_sha,
                    "replacement_utf8": "function greet(): string {\n  return \"hello\";\n}"
                }]
            }
        }
    }));
    assert_eq!(ok_patch["result"]["isError"], false);
    let packet_id = ok_patch["result"]["structuredContent"]["packet_id"]
        .as_str()
        .unwrap()
        .to_string();

    // 6. splice_verify
    let ver = rpc(json!({
        "jsonrpc": "2.0", "id": 6, "method": "tools/call",
        "params": {"name": "splice_verify", "arguments": {"packet_id": packet_id}}
    }));
    assert_eq!(ver["result"]["isError"], false);
    let bundle_id = ver["result"]["structuredContent"]["bundle_id"]
        .as_str()
        .unwrap()
        .to_string();

    // 7. splice_project
    let proj = rpc(json!({
        "jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": {
            "name": "splice_project",
            "arguments": {"packet_id": packet_id, "bundle_id": bundle_id}
        }
    }));
    assert_eq!(proj["result"]["isError"], false);
    assert!(!proj["result"]["structuredContent"]["commit_sha"]
        .as_str()
        .unwrap()
        .is_empty());

    drop(stdin);
    let status = child.wait().unwrap();
    assert!(status.success());

    let final_ts = fs::read_to_string(tmp.path().join("src/hello.ts")).unwrap();
    assert!(final_ts.starts_with("// Keep banner\nexport "));
    assert!(final_ts.contains("return \"hello\";"));
}

#[test]
fn cli_process_roundtrip_and_policy_guards() {
    let tmp = TempDir::new().unwrap();
    init_git_repo(tmp.path());
    fs::create_dir_all(tmp.path().join("src")).unwrap();
    fs::create_dir_all(tmp.path().join(".mde")).unwrap();
    fs::write(
        tmp.path().join("src/core.c"),
        "/* keep */\nint inc(int x) {\n    return x + 1;\n}\n",
    )
    .unwrap();
    commit_all(tmp.path(), "seed core.c");

    let bin = env!("CARGO_BIN_EXE_mde");
    let root_arg = tmp.path().to_str().unwrap();

    // 1. CLI locate persists session read_token across process boundaries.
    let loc_out = Command::new(bin)
        .args(["--root", root_arg, "locate", "src/core.c"])
        .output()
        .unwrap();
    assert!(loc_out.status.success());
    let loc_json: Value = serde_json::from_slice(&loc_out.stdout).unwrap();
    let inc = &loc_json["symbols"][0];
    assert_eq!(inc["symbol"], "inc");

    // 2. CLI patch consumes persisted read_token and emits packet.
    let patch_spec = json!({
        "capability_id": "cap.core.inc",
        "read_tokens": [inc["read_token"]],
        "commit_subject": "core: increment by 2",
        "edits": [{
            "path": "src/core.c",
            "start_byte": inc["start_byte"],
            "end_byte": inc["end_byte"],
            "expected_old_sha256": inc["span_sha256"],
            "replacement_utf8": "int inc(int x) {\n    return x + 2;\n}"
        }]
    });
    let spec_file = tmp.path().join("patch_spec.json");
    fs::write(&spec_file, serde_json::to_vec(&patch_spec).unwrap()).unwrap();
    let patch_out = Command::new(bin)
        .args([
            "--root",
            root_arg,
            "patch",
            "--spec",
            spec_file.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        patch_out.status.success(),
        "cli patch failed: {}",
        String::from_utf8_lossy(&patch_out.stderr)
    );
    let pkt_json: Value = serde_json::from_slice(&patch_out.stdout).unwrap();
    let pkt_id = pkt_json["packet_id"].as_str().unwrap();

    // 3. CLI verify and project complete the lifecycle.
    let ver_out = Command::new(bin)
        .args(["--root", root_arg, "verify", pkt_id])
        .output()
        .unwrap();
    assert!(ver_out.status.success());
    let bundle_json: Value = serde_json::from_slice(&ver_out.stdout).unwrap();
    let bundle_id = bundle_json["bundle_id"].as_str().unwrap();

    let proj_out = Command::new(bin)
        .args(["--root", root_arg, "project", pkt_id, bundle_id])
        .output()
        .unwrap();
    assert!(proj_out.status.success());

    let updated_c = fs::read_to_string(tmp.path().join("src/core.c")).unwrap();
    assert!(updated_c.starts_with("/* keep */\n"));
    assert!(updated_c.contains("return x + 2;"));

    // 4. Policy guards: budget cap, verb allowlist, and Zone B missing cassette fail closed.
    let mut policy = PolicyConfig {
        max_evals: 2,
        ..Default::default()
    };
    policy.anchors.push(AnchorSpec {
        anchor_id: "zone_b_uncached".into(),
        tier: 1,
        visibility: "visible".into(),
        zone: "B".into(),
        cmd: vec!["true".into()],
        path_prefixes: vec!["src/".into()],
        cassette_sha256: None,
    });
    fs::write(
        tmp.path().join(".mde/policy.json"),
        serde_json::to_vec_pretty(&policy).unwrap(),
    )
    .unwrap();

    let broker = Broker::open(tmp.path(), false).unwrap();
    let budget_err = broker
        .splice_verify(VerifyRequest {
            packet_id: pkt_id.to_string(),
            eval_count: Some(3),
        })
        .unwrap_err();
    assert_eq!(budget_err.code, "ERR_BUDGET_EXCEEDED");

    let zone_b_err = broker
        .splice_verify(VerifyRequest {
            packet_id: pkt_id.to_string(),
            eval_count: Some(1),
        })
        .unwrap_err();
    assert_eq!(zone_b_err.code, "ERR_ZONE_B_NO_CASSETTE");

    policy.allowed_verbs.retain(|v| v != "splice_verify");
    fs::write(
        tmp.path().join(".mde/policy.json"),
        serde_json::to_vec_pretty(&policy).unwrap(),
    )
    .unwrap();
    let denied_err = broker
        .splice_verify(VerifyRequest {
            packet_id: pkt_id.to_string(),
            eval_count: Some(1),
        })
        .unwrap_err();
    assert_eq!(denied_err.code, "ERR_POLICY_DENIED");
}

#[test]
fn inline_prose_and_formal_proof_zone_tags_in_code_files() {
    let tmp = TempDir::new().unwrap();
    fs::create_dir_all(tmp.path().join("src")).unwrap();
    let rs = concat!(
        "/// Plain language module doc.\n",
        "pub fn compute(x: i32) -> i32 { x + 1 }\n",
        "/// @formal-proof data-eido-skip\n",
        "pub fn checked_invariant(x: i32) -> bool { x == x }\n",
    );
    fs::write(tmp.path().join("src/mixed.rs"), rs).unwrap();

    let mut broker = Broker::open(tmp.path(), false).unwrap();
    let loc = broker
        .splice_locate(LocateRequest {
            path: "src/mixed.rs".into(),
            capability_id: None,
        })
        .unwrap();

    assert!(
        loc.symbols.iter().any(|s| s.zone == Zone::Prose),
        "expected Rust doc comment tagged as Zone::Prose"
    );
    assert!(
        loc.symbols.iter().any(|s| s.zone == Zone::FormalProof),
        "expected @formal-proof span tagged as Zone::FormalProof"
    );
    assert!(
        loc.symbols.iter().any(|s| s.symbol == "compute" && s.zone == Zone::Code),
        "expected standard function tagged as Zone::Code"
    );
}
