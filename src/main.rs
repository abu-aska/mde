use clap::{Parser, Subcommand};
use mde::broker::{
    Broker, LocateRequest, PatchRequest, ProjectRequest, TraceRequest, VerifyRequest,
};
use mde::mcp::run_stdio_server;
use std::fs;
use std::io::{self, BufReader};
use std::path::PathBuf;
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
    Verify {
        packet_id: String,
    },
    /// Project a verified Splice Packet and Evidence Bundle into a minimal Git commit
    Project {
        packet_id: String,
        bundle_id: String,
        #[arg(long)]
        approve_diff_sha256: Option<String>,
    },
    /// Start JSON-RPC 2.0 stdio MCP server
    Mcp,
}

fn main() {
    let cli = Cli::parse();
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
            .and_then(|raw| {
                serde_json::from_str::<PatchRequest>(&raw)
                    .map_err(|e| mde::types::MdeError::new("ERR_INVALID_ARGS", format!("{e}")))
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
    };

    if let Err(err) = result {
        eprintln!(
            "{}",
            serde_json::to_string(&err).unwrap_or_else(|_| err.to_string())
        );
        process::exit(1);
    }
}

fn read_json_input(spec: &str) -> mde::types::MdeResult<String> {
    if spec == "-" {
        let mut buf = String::new();
        io::Read::read_to_string(&mut io::stdin(), &mut buf)
            .map_err(|e| mde::types::MdeError::new("ERR_IO", format!("stdin read: {e}")))?;
        Ok(buf)
    } else {
        fs::read_to_string(spec)
            .map_err(|e| mde::types::MdeError::new("ERR_IO", format!("spec read {spec}: {e}")))
    }
}

fn print_json<T: serde::Serialize>(val: T) -> mde::types::MdeResult<()> {
    let text = serde_json::to_string_pretty(&val)
        .map_err(|e| mde::types::MdeError::new("ERR_SERIALIZE", format!("{e}")))?;
    println!("{text}");
    Ok(())
}
