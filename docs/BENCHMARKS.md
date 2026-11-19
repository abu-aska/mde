# Conformance Benchmarks

Measured release-build latency and gate pass rates for `siliconcordat/mde` on a real multi-language corpus.

## Environment and corpus

- **Platform:** Apple M1 Max (`aarch64`, macOS 27.0.1), `rustc 1.99.1`, `cargo 1.99.1`, `--release` profile.
- **Reproduce command:** `cargo run --release --example bench_corpus` and `cargo test`.
- **Clean corpus:** 19 files (`146,323` bytes total): all 9 Rust source files in `src/` plus 10 clean fixtures in `tests/fixtures/` covering Rust, Python, C, TypeScript, TSX, Lean, Markdown, and JSON.
- **Adversarial corpus:** 4 broken-syntax fixtures (`rust`, `python`, `c`, `typescript`) plus 2 macro-opaque fixtures (`c` `#ifdef`/`#define`, `rust` `macro_rules!`/macro invocation).

## Measured latency (release build)

| Operation | Scope | Measured avg latency (ms) |
| --- | --- | --- |
| `analyze_file` + G1.1 0-byte round-trip | 19 clean files x 10 rounds (`146,323` B/round) | `1.577` ms / file |
| `splice_locate` | 4 language fixtures (Rust, Python, C, TS) | `0.355` ms / call |
| `splice_trace` | 4 language fixtures with symbol scan | `0.355` ms / call |
| `splice_patch` | 4 language fixtures (includes `git rev-parse` + regex scan) | `26.671` ms / call |
| `splice_verify` | 4 language fixtures in isolated scratch copy | `2.266` ms / call |
| `mde guard` | 3 repo markdown docs (`README.md`, `PROTOCOL.md`, `PLAN.md`) x 10 rounds | `16.292` ms / run |
| `mde zone-manifest --verify` | `schemas/zone-manifest.v0.1.json` x 10 rounds | `0.097` ms / call |

`splice_patch` latency is dominated by two `git rev-parse` subprocess calls (`HEAD` and `HEAD^{tree}`) plus per-call regex compilation in secret scanning. In-process CST parsing, byte-span splicing, and SHA-256 verification take under 2 ms.

## Conformance gate pass rates

| Gate | Requirement | Result | Evidence |
| --- | --- | --- | --- |
| G1.1 | 0-byte identity round-trip | `19/19` files (`190/190` passes) | `real_corpus_g1_1_zero_byte_identity_across_src_and_fixtures` |
| G1.2 | Strict byte-span diff with sibling comments and pragmas preserved | `4/4` languages (`100%`) | `real_corpus_g1_2_strict_span_splice_across_four_languages` |
| G1.3 | Hard refusal (`ERR_SYNTAX_ERROR_REGION`) on broken syntax | `4/4` languages (`100%`) | `real_corpus_g1_3_broken_syntax_refusal_across_four_languages` |
| G1.4 | Hard refusal (`ERR_MACRO_OPAQUE`) on C `#ifdef` and Rust macros | `2/2` languages (`100%`) | `real_corpus_g1_4_macro_opacity_refusal_in_c_and_rust` |
| Zone manifest | Canonical 5-zone schema digest + classification (`prose`, `code`, `formal_proof`, `ui_module`, `condensed_json`) | `5/5` zones (`100%`) | `zone_manifest_schema_matches_compiled_rules_and_classifies_five_zones` |
| Native guard | Prose tells, semicolons, duplicate refs, forecasts, secrets, local paths, call policy | `8/8` rules + `2/2` policy checks | `native_rust_guard_checks_all_rules_and_blocks_dirty_prose_splice` |

## Real-corpus grammar finding

Running G1.1 on `mde`'s own `src/*.rs` uncovered a real `tree-sitter-rust 0.23.3` grammar quirk: in Rust 2024 edition syntax, `&raw` starts a raw-pointer borrow (`&raw const` or `&raw mut`), so a Rust 2021 variable named `raw` passed as `&raw` produced false `ERROR` nodes in `tree-sitter-rust`. Renaming those locals to `raw_text` eliminated all false errors in `src/`. Splicing external Rust 2021 files that borrow a variable named `raw` will hit `ERR_SYNTAX_ERROR_REGION` until `tree-sitter-rust` disambiguates `&raw` without a following `const`/`mut`.
