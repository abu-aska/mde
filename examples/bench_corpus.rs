use mde::broker::{
    Broker, LocateRequest, PatchEditInput, PatchRequest, TraceRequest, VerifyRequest,
};
use mde::cst::{analyze_file, apply_byte_span_edits};
use mde::guard::{check_files, GuardOptions};
use mde::zone_manifest::verify_zone_manifest_file;
use std::fs;
use std::path::PathBuf;
use std::time::Instant;
use tempfile::TempDir;

fn main() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    // Build real corpus list: all mde src/*.rs + all clean multi-language fixtures.
    let mut clean_files: Vec<String> = Vec::new();
    for entry in fs::read_dir(root.join("src")).unwrap().flatten() {
        let p = entry.path();
        if p.extension().and_then(|e| e.to_str()) == Some("rs") {
            clean_files.push(
                p.strip_prefix(&root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/"),
            );
        }
    }
    for rel in [
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
    ] {
        clean_files.push(rel.to_string());
    }
    clean_files.sort();

    let total_bytes: usize = clean_files
        .iter()
        .map(|f| fs::metadata(root.join(f)).unwrap().len() as usize)
        .sum();

    // 1. G1.1 zero-byte round-trip + analyze across all clean files (10 passes).
    let rounds = 10usize;
    let t0 = Instant::now();
    let mut g1_1_passed = 0usize;
    for _ in 0..rounds {
        for rel in &clean_files {
            let bytes = fs::read(root.join(rel)).unwrap();
            let parsed = analyze_file(rel, &bytes).unwrap();
            let rt = apply_byte_span_edits(rel, &bytes, &[]).unwrap();
            if parsed.error_spans.is_empty() && rt == bytes {
                g1_1_passed += 1;
            }
        }
    }
    let locate_total_ms = t0.elapsed().as_secs_f64() * 1000.0;
    let locate_per_file_ms = locate_total_ms / (rounds * clean_files.len()) as f64;

    // 2. Broker verbs: splice_locate, splice_trace, splice_patch, splice_verify across 4 languages.
    let splice_cases: &[(&str, &str, &str, &str)] = &[
        (
            "tests/fixtures/rust/sample_service.rs",
            "src/sample_service.rs",
            "merge_counts",
            "pub fn merge_counts(a: &BTreeMap<String, u64>, b: &BTreeMap<String, u64>) -> BTreeMap<String, u64> {\n    let mut out = b.clone();\n    for (k, v) in a {\n        *out.entry(k.clone()).or_insert(0) += v;\n    }\n    out\n}",
        ),
        (
            "tests/fixtures/python/ledger_worker.py",
            "src/ledger_worker.py",
            "compute_score",
            "def compute_score(entries: list[Entry]) -> int:  # type: ignore[misc]\n    \"\"\"Sum positive entry values.\"\"\"\n    return sum(item.value for item in entries if item.value > 0)",
        ),
        (
            "tests/fixtures/c/ring_buffer.c",
            "src/ring_buffer.c",
            "ring_count",
            "size_t ring_count(const RingBuf *r) {\n    return (size_t)((r->head - r->tail) & 63u);\n}",
        ),
        (
            "tests/fixtures/typescript/api_client.ts",
            "src/api_client.ts",
            "formatHeader",
            "function formatHeader(rec: DigestRecord): string {\n  return `${rec.id}=${rec.sha256}`;\n}",
        ),
    ];

    let mut locate_ms_sum = 0.0;
    let mut trace_ms_sum = 0.0;
    let mut patch_ms_sum = 0.0;
    let mut verify_ms_sum = 0.0;
    let mut g1_2_passed = 0usize;

    for (fixture, dest_rel, sym_name, repl) in splice_cases {
        let tmp = TempDir::new().unwrap();
        let src_bytes = fs::read(root.join(fixture)).unwrap();
        let dest = tmp.path().join(dest_rel);
        fs::create_dir_all(dest.parent().unwrap()).unwrap();
        fs::write(&dest, &src_bytes).unwrap();

        let mut broker = Broker::open(tmp.path(), false).unwrap();

        let tl = Instant::now();
        let loc = broker
            .splice_locate(LocateRequest {
                path: (*dest_rel).into(),
                capability_id: None,
            })
            .unwrap();
        locate_ms_sum += tl.elapsed().as_secs_f64() * 1000.0;

        let tt = Instant::now();
        let _trace = broker
            .splice_trace(TraceRequest {
                path: (*dest_rel).into(),
                symbol: Some((*sym_name).into()),
            })
            .unwrap();
        trace_ms_sum += tt.elapsed().as_secs_f64() * 1000.0;

        let sym = loc.symbols.iter().find(|s| s.symbol == *sym_name).unwrap();
        let tp = Instant::now();
        let pkt = broker
            .splice_patch(PatchRequest {
                capability_id: format!("bench.{sym_name}"),
                read_tokens: vec![sym.read_token.clone()],
                edits: vec![PatchEditInput {
                    path: (*dest_rel).into(),
                    start_byte: sym.start_byte,
                    end_byte: sym.end_byte,
                    expected_old_sha256: sym.span_sha256.clone(),
                    replacement_utf8: (*repl).into(),
                    anchor_symbol: Some((*sym_name).into()),
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
        patch_ms_sum += tp.elapsed().as_secs_f64() * 1000.0;

        let patched = apply_byte_span_edits(dest_rel, &src_bytes, &pkt.edits).unwrap();
        if patched[..sym.start_byte] == src_bytes[..sym.start_byte]
            && patched.ends_with(&src_bytes[sym.end_byte..])
        {
            g1_2_passed += 1;
        }

        let tv = Instant::now();
        let bundle = broker
            .splice_verify(VerifyRequest {
                packet_id: pkt.packet_id,
                eval_count: None,
            })
            .unwrap();
        verify_ms_sum += tv.elapsed().as_secs_f64() * 1000.0;
        assert_eq!(bundle.summary.lexicase_grade, "canonical");
    }

    // 3. Guard and zone-manifest timings (10 passes).
    let docs = vec![
        root.join("README.md").to_string_lossy().into_owned(),
        root.join("PROTOCOL.md").to_string_lossy().into_owned(),
        root.join("PLAN.md").to_string_lossy().into_owned(),
    ];
    let opts = GuardOptions::default();
    let tg = Instant::now();
    for _ in 0..rounds {
        let rep = check_files(&docs, &opts).unwrap();
        assert!(rep.passed);
    }
    let guard_ms = (tg.elapsed().as_secs_f64() * 1000.0) / rounds as f64;

    let schema_path = root.join("schemas/zone-manifest.v0.1.json");
    let tz = Instant::now();
    for _ in 0..rounds {
        let _ = verify_zone_manifest_file(&schema_path).unwrap();
    }
    let zone_manifest_ms = (tz.elapsed().as_secs_f64() * 1000.0) / rounds as f64;

    let n = splice_cases.len() as f64;
    println!("clean_corpus_files={}", clean_files.len());
    println!("clean_corpus_bytes={total_bytes}");
    println!(
        "g1_1_identity={}/{}",
        g1_1_passed,
        rounds * clean_files.len()
    );
    println!("g1_2_strict_span={}/{}", g1_2_passed, splice_cases.len());
    println!("analyze_and_roundtrip_ms_per_file={locate_per_file_ms:.3}");
    println!("splice_locate_avg_ms={:.3}", locate_ms_sum / n);
    println!("splice_trace_avg_ms={:.3}", trace_ms_sum / n);
    println!("splice_patch_avg_ms={:.3}", patch_ms_sum / n);
    println!("splice_verify_avg_ms={:.3}", verify_ms_sum / n);
    println!("mde_guard_3_docs_avg_ms={guard_ms:.3}");
    println!("zone_manifest_verify_avg_ms={zone_manifest_ms:.3}");
}
