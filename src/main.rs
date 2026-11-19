use clap::{Parser, Subcommand};
use mde::broker::{
    Broker, LocateRequest, PatchRequest, ProjectRequest, TraceRequest, VerifyRequest,
};
use mde::guard::{
    check_files, check_sources, evaluate_call_policy, CallPolicyRequest, GuardOptions,
    DEFAULT_MAX_PARAGRAPH_CHARS,
};
use mde::integrity::{verify_manifest, write_manifest, DEFAULT_MANIFEST_NAME};
use mde::mcp::run_stdio_server;
use mde::policy::PolicyConfig;
use mde::seam::{verify_all_seams, verify_seam_manifest};
use mde::types::{MdeError, MdeResult};
use mde::zone_manifest::{build_zone_manifest, verify_zone_manifest_file};
use std::fs;
use std::io::{self, BufReader};
use std::path::{Path, PathBuf};
use std::process;

#[derive(Parser)]
#[command(name = "mde", version, about = "L5 Improved MCP CST broker")]
struct Cli {
    /// Repository root directory (defaults to current directory)
    #[arg(long, global = true, default_value = ".")]
    root: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Locate CST symbols, byte spans, syntactic zones, and mint read tokens
    Locate {
        path: String,
        #[arg(long)]
        capability_id: Option<String>,
    },
    /// Trace references, mapped anchors, dynamic sites, and risk triggers
    Trace {
        path: String,
        #[arg(long)]
        symbol: Option<String>,
    },
    /// Apply byte-span edits described in a JSON file and emit a Splice Packet
    Patch {
        /// Path to PatchRequest JSON file (or '-' for stdin)
        #[arg(long)]
        spec: String,
    },
    /// Verify a Splice Packet in an isolated workspace and emit an Evidence Bundle
    Verify { packet_id: String },
    /// Project a verified Splice Packet and Evidence Bundle into a minimal Git commit
    Project {
        packet_id: String,
        bundle_id: String,
        #[arg(long)]
        approve_diff_sha256: Option<String>,
    },
    /// Run deterministic prose, duplicate-reference, secret/path, and call-policy guard
    Guard {
        /// Files to check
        files: Vec<String>,
        /// Check inline text instead of files
        #[arg(long)]
        text: Option<String>,
        /// Run duplicate reference check (--dupes parity; enabled by default unless --no-dupes)
        #[arg(long)]
        dupes: bool,
        /// Check only duplicate references
        #[arg(long)]
        dupes_only: bool,
        /// Flag standalone @-mentions
        #[arg(long)]
        check_mentions: bool,
        /// Validate a JSON CallPolicyRequest file (or '-' for stdin) against repo policy
        #[arg(long)]
        call_policy: Option<String>,
        /// Emit machine-readable JSON output
        #[arg(long)]
        json: bool,
    },
    /// Emit or verify the canonical SHA-256 Vertical Zone Manifest (L5 -> L4/L2/L1)
    ZoneManifest {
        /// Write canonical zone manifest JSON to this path
        #[arg(long)]
        out: Option<PathBuf>,
        /// Verify an existing zone manifest file against compiled rules and digest
        #[arg(long)]
        verify: Option<PathBuf>,
    },
    /// Write or verify Plane 1 SHA256SUMS / MANIFEST.sha256 integrity manifests
    Integrity {
        /// Rewrite manifest from the repository tree
        #[arg(long, conflicts_with = "verify")]
        write: bool,
        /// Verify repository tree against manifest
        #[arg(long, conflicts_with = "write")]
        verify: bool,
        /// Manifest filename at repository root (SHA256SUMS or MANIFEST.sha256)
        #[arg(long, default_value = DEFAULT_MANIFEST_NAME)]
        manifest: String,
        /// Do not fail verification on unlisted files (report only)
        #[arg(long)]
        allow_unlisted: bool,
    },
    /// Verify cross-repo capability vendoring manifests under vendor/splices/<name>/splice.json
    SeamVerify {
        /// Optional single manifest path; omit to scan all vendor/splices/*/splice.json
        manifest_path: Option<String>,
    },
    /// Start JSON-RPC 2.0 stdio MCP server
    Mcp,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Guard {
            files,
            text,
            dupes: _,
            dupes_only,
            check_mentions,
            call_policy,
            json,
        } => {
            let exit_code = run_guard_cli(
                &cli.root,
                files,
                text,
                dupes_only,
                check_mentions,
                call_policy,
                json,
            );
            process::exit(exit_code);
        }
        Commands::ZoneManifest { out, verify } => {
            if let Err(err) = run_zone_manifest_cli(out, verify) {
                eprintln!(
                    "{}",
                    serde_json::to_string(&err).unwrap_or_else(|_| err.to_string())
                );
                process::exit(1);
            }
            return;
        }
        Commands::Integrity {
            write,
            verify,
            manifest,
            allow_unlisted,
        } => {
            let code = run_integrity_cli(&cli.root, write, verify, &manifest, !allow_unlisted);
            process::exit(code);
        }
        Commands::SeamVerify { manifest_path } => {
            let code = run_seam_verify_cli(&cli.root, manifest_path);
            process::exit(code);
        }
        _ => {}
    }

    let persist_tokens = !matches!(cli.command, Commands::Mcp);
    let mut broker = match Broker::open(&cli.root, persist_tokens) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("{}", serde_json::to_string(&e).unwrap_or_else(|_| e.to_string()));
            process::exit(1);
        }
    };

    let result = match cli.command {
        Commands::Locate {
            path,
            capability_id,
        } => broker
            .splice_locate(LocateRequest {
                path,
                capability_id,
            })
            .and_then(print_json),
        Commands::Trace { path, symbol } => broker
            .splice_trace(TraceRequest { path, symbol })
            .and_then(print_json),
        Commands::Patch { spec } => read_json_input(&spec)
            .and_then(|raw_text| {
                serde_json::from_str::<PatchRequest>(&raw_text)
                    .map_err(|e| MdeError::new("ERR_INVALID_ARGS", format!("{e}")))
            })
            .and_then(|req| broker.splice_patch(req))
            .and_then(print_json),
        Commands::Verify { packet_id } => broker
            .splice_verify(VerifyRequest {
                packet_id,
                eval_count: None,
            })
            .and_then(print_json),
        Commands::Project {
            packet_id,
            bundle_id,
            approve_diff_sha256,
        } => broker
            .splice_project(ProjectRequest {
                packet_id,
                bundle_id,
                approve_diff_sha256,
            })
            .and_then(print_json),
        Commands::Mcp => {
            let stdin = io::stdin();
            let stdout = io::stdout();
            run_stdio_server(&mut broker, BufReader::new(stdin.lock()), stdout.lock())
        }
        Commands::Guard { .. }
        | Commands::ZoneManifest { .. }
        | Commands::Integrity { .. }
        | Commands::SeamVerify { .. } => unreachable!(),
    };

    if let Err(err) = result {
        eprintln!(
            "{}",
            serde_json::to_string(&err).unwrap_or_else(|_| err.to_string())
        );
        process::exit(1);
    }
}

fn run_guard_cli(
    root: &Path,
    files: Vec<String>,
    text: Option<String>,
    dupes_only: bool,
    check_mentions: bool,
    call_policy: Option<String>,
    json_out: bool,
) -> i32 {
    let policy = PolicyConfig::load(root).unwrap_or_default();

    if let Some(spec) = call_policy {
        let raw_text = match read_json_input(&spec) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("{e}");
                return 3;
            }
        };
        let req: CallPolicyRequest = match serde_json::from_str(&raw_text) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("invalid call policy request: {e}");
                return 3;
            }
        };
        let rep = evaluate_call_policy(root, &req, &policy);
        if json_out {
            println!("{}", serde_json::to_string_pretty(&rep).unwrap_or_default());
        } else if rep.allowed {
            println!("mde guard call-policy: allowed ({})", rep.verb);
        } else if let Some(err) = rep.rejection {
            eprintln!("mde guard call-policy: DENIED ({})", err);
        }
        return if rep.allowed { 0 } else { 1 };
    }

    let opts = GuardOptions {
        check_prose: !dupes_only,
        check_dupes: true,
        check_secrets: !dupes_only,
        check_mentions,
        max_paragraph_chars: DEFAULT_MAX_PARAGRAPH_CHARS,
        max_trace_bytes: policy.max_trace_bytes,
        extra_forbidden_patterns: policy.extra_forbidden_patterns,
    };

    let report = if let Some(ref txt) = text {
        check_sources(&[("<text>", txt.as_str())], &opts)
    } else if !files.is_empty() {
        match check_files(&files, &opts) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("{e}");
                return 3;
            }
        }
    } else {
        eprintln!("usage: mde guard <files...> | --text <str> | --call-policy <spec>");
        return 3;
    };

    if json_out {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_default()
        );
    } else if report.passed {
        println!(
            "mde guard: clean ({} file(s), {} lines)",
            report.files_checked, report.total_lines
        );
    } else {
        println!(
            "mde guard: {} finding(s). DO NOT POST:",
            report.findings.len()
        );
        for f in &report.findings {
            println!("  {}:{}: [{}] {}", f.path, f.line, f.rule, f.message);
        }
    }

    if report.passed { 0 } else { 1 }
}

fn run_zone_manifest_cli(out: Option<PathBuf>, verify: Option<PathBuf>) -> MdeResult<()> {
    if let Some(path) = verify {
        let verified = verify_zone_manifest_file(&path)?;
        return print_json(verified);
    }
    let manifest = build_zone_manifest()?;
    let encoded = serde_json::to_string_pretty(&manifest)
        .map_err(|e| MdeError::new("ERR_SERIALIZE", format!("{e}")))?;
    if let Some(dest) = out {
        if let Some(parent) = dest.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)
                    .map_err(|e| MdeError::new("ERR_IO", format!("mkdir failed: {e}")))?;
            }
        }
        fs::write(&dest, format!("{encoded}\n"))
            .map_err(|e| MdeError::new("ERR_IO", format!("write manifest failed: {e}")))?;
    } else {
        println!("{encoded}");
    }
    Ok(())
}

fn run_integrity_cli(
    root: &Path,
    write: bool,
    verify: bool,
    manifest: &str,
    strict_unlisted: bool,
) -> i32 {
    if !write && !verify {
        eprintln!("usage: mde integrity --write | --verify [--manifest SHA256SUMS]");
        return 2;
    }
    if write {
        match write_manifest(root, manifest) {
            Ok(res) => {
                let _ = print_json(res);
                0
            }
            Err(err) => {
                eprintln!(
                    "{}",
                    serde_json::to_string(&err).unwrap_or_else(|_| err.to_string())
                );
                1
            }
        }
    } else {
        match verify_manifest(root, manifest, strict_unlisted) {
            Ok(rep) => {
                let ok = rep.ok;
                let _ = print_json(rep);
                if ok { 0 } else { 1 }
            }
            Err(err) => {
                eprintln!(
                    "{}",
                    serde_json::to_string(&err).unwrap_or_else(|_| err.to_string())
                );
                1
            }
        }
    }
}

fn run_seam_verify_cli(root: &Path, manifest_path: Option<String>) -> i32 {
    if let Some(rel) = manifest_path {
        match verify_seam_manifest(root, &rel) {
            Ok(rep) => {
                let ok = rep.ok;
                let _ = print_json(rep);
                if ok { 0 } else { 1 }
            }
            Err(err) => {
                eprintln!(
                    "{}",
                    serde_json::to_string(&err).unwrap_or_else(|_| err.to_string())
                );
                1
            }
        }
    } else {
        match verify_all_seams(root) {
            Ok(suite) => {
                let ok = suite.ok;
                let _ = print_json(suite);
                if ok { 0 } else { 1 }
            }
            Err(err) => {
                eprintln!(
                    "{}",
                    serde_json::to_string(&err).unwrap_or_else(|_| err.to_string())
                );
                1
            }
        }
    }
}

fn read_json_input(spec: &str) -> MdeResult<String> {
    if spec == "-" {
        let mut buf = String::new();
        io::Read::read_to_string(&mut io::stdin(), &mut buf)
            .map_err(|e| MdeError::new("ERR_IO", format!("stdin read: {e}")))?;
        Ok(buf)
    } else {
        fs::read_to_string(spec)
            .map_err(|e| MdeError::new("ERR_IO", format!("spec read {spec}: {e}")))
    }
}

fn print_json<T: serde::Serialize>(val: T) -> MdeResult<()> {
    let text = serde_json::to_string_pretty(&val)
        .map_err(|e| MdeError::new("ERR_SERIALIZE", format!("{e}")))?;
    println!("{text}");
    Ok(())
}
