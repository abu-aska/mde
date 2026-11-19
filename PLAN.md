# MDE Implementation Plan

This plan tracks the staged rollout of `siliconcordat/mde`, the Layer 5 Improved MCP protocol and local CST broker.

## Milestone 1: Protocol specification and repository foundation

- Publish `README.md`, `LICENSE` (Apache-2.0), `PROTOCOL.md`, and `PLAN.md`.
- Define canonical `splice-packet/v0.1` and `evidence-bundle/v0.1` JSON schemas.
- Separate intra-repo CST editing (Profile A) from cross-repo capability vendoring (`vendor/splices/`) and open-weights slot metadata (Profile B in vendor-namespaced `_meta`).

## Milestone 2: Rust `mde` v0.1 CLI and stdio MCP server

Build a single-binary Rust crate with minimal dependencies (`tree-sitter`, language grammars for Rust, Python, C, and TypeScript, `serde`, `serde_json`, `sha2`, `clap`, `regex`):

1. **CST engine and zone classifier:** Parse Rust, Python, C, and TypeScript into raw `&[u8]` byte spans. Tag every span with syntactic zone metadata (`prose`, `code`, `formal_proof`, `ui_module`) for downstream consumption by Layer 4 (`exo`) and Layer 2 (`weft`).
2. **Five-verb broker over CLI and JSON-RPC 2.0 stdio MCP:** Implement `splice_locate`, `splice_trace`, `splice_patch`, `splice_verify`, and `splice_project`.
3. **Mechanical safety guards:**
   - Session `read_token` enforcement before `splice_patch`.
   - Hard refusal inside Tree-sitter `ERROR`/`MISSING` ancestors (Gate G1.3) and C/Rust macro-opaque regions (Gate G1.4).
   - Path confinement and read-only lock blocking edits to protected oracle paths (Gate G3.4).
   - Secret and local-path scanner failing closed on leaks or trace size caps (Gate G6.4).
   - Risk classifier requiring exact diff SHA-256 human approval for high-risk paths (`auth`, `public_api`, `schema`, `infra`, `anchors`) during `splice_project` (Gate G7.3).
4. **Automated conformance test suite:**
   - Gate G1.1: 0-byte identity round-trip across C, Rust, Python, and TypeScript.
   - Gate G1.2: Strict byte-span edit blast radius with untouched sibling comments and pragmas preserved.
   - Gate G1.3 and G1.4: Hard refusals on broken syntax and macro regions.
   - Gate G3.4: Refusal on protected test/oracle path edits and post-verify tamper check.
   - Gate G4.1 and G4.3: Lossless minimal Git commit projection and clean re-ingest after plain Git edits.
   - Gate G6.4: Fail-closed secret and path scrubbing.
   - End-to-end JSON-RPC 2.0 stdio MCP protocol round-trip across all five verbs.

## Milestone 3: v0.2 integrations (deferred until v0.1 proves out)

- LSP and SCIP cross-file reference providers behind `splice_trace`.
- Multi-packet composed tree verification (`--compose-with`) and 10x randomized-order anchor flake quarantine runner.
- Detached Ed25519 signature verification for verifier-owned Evidence Bundles.
- Live Profile B W-MCP bridge to Layer 3 `warp-modeld` over Unix domain socket.
