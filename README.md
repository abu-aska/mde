# mde

`mde` is the Layer 5 protocol and local tool broker for the Siliconcordat stack. It lets any coding agent read, trace, edit, verify, and commit code through exact syntax spans instead of fragile text diffs.

Any tool or model that speaks JSON-RPC over stdio (Model Context Protocol, or MCP) can connect to `mde`. Humans stay in control of approvals, tests, and Git history.

## What `mde` solves

Standard MCP servers dump large tool lists and prose rules into prompts on every turn. They do not block an agent from editing an unread file, changing a test file to make a check pass, or breaking syntax inside macros.

`mde` fixes those failure modes in software instead of prompt rules:

- **Read before write:** Every edit requires a short-lived `read_token` minted when the file was read at its exact current SHA-256 digest.
- **Byte-exact syntax edits:** Tree-sitter parses Rust, Python, C, and TypeScript into concrete syntax trees (CSTs). Edits splice raw byte ranges so untouched comments, blank lines, and directives stay byte-identical.
- **Hard refusals on unsafe syntax:** Edits inside Tree-sitter `ERROR` or `MISSING` nodes, or inside C preprocessor and Rust macro regions, are rejected before writing a byte.
- **Protected test locks:** Paths marked as tests or anchors cannot be edited during normal code changes.
- **Zone classification:** Each located span carries a syntactic zone tag (`prose`, `code`, `formal_proof`, or `ui_module`) so the Layer 4 harness (`exo`) and Layer 2 model runtime (`weft`) can pick the right checks and adapter scales.
- **Plain Git output:** Verified changes project to normal minimal Git commits. Any engineer can edit files with a plain text editor and commit with standard `git`.

## Stack position

`mde` sits at Layer 5 of the Siliconcordat stack (formerly named `mep` for Plane 1 text integrity and expanded to cover structural editing and vendor-namespaced weight-slot metadata):

| Layer | Repo | Role |
| --- | --- | --- |
| L5 | `siliconcordat/mde` | Improved MCP broker, CST splicer, Plane 1 lineage, W-MCP `_meta` contract |
| L4 | `siliconcordat/exo` | Agent harness, exact-byte human approval gate, memory, zone router |
| L3 | `siliconcordat/warp` | OS runtime, sandboxes, load-time model gate (`warp-modeld`) |
| L2 | `siliconcordat/weft` | Deterministic weight compiler, certificates, multi-adapter artifacts |
| L1 | `siliconcordat/loom` | Hardware research and architecture theory |

## Repository layout

- `PROTOCOL.md`: Complete L5 wire protocol, 5-verb contract, JSON schemas, call guard rules, Plane 1 lineage, and vendor-namespaced weight-slot `_meta`.
- `PLAN.md`: Implementation milestones, conformance gates, and explicit deferrals.
- `Cargo.toml`, `src/`, `tests/`: Rust `mde` CLI binary, stdio JSON-RPC MCP server, Tree-sitter CST engine, and automated conformance tests.

## Quickstart

```sh
cargo test
cargo run -- locate path/to/file.rs
cargo run -- mcp
```

## License

Code is licensed under the Apache License, Version 2.0 (`LICENSE`). Documentation is licensed under CC BY 4.0.
