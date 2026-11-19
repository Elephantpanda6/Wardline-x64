#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};
use wardline_core::IsolationLevel;
use wardline_guard::DEFAULT_PIPE_NAME;
use wardline_mcp::registry::{check_server_entry, McpRegistry, McpServerEntry};
use wardline_mcp::wrap::{WrapConfig, WrappedMcpProxy};
use wardline_mcp::{McpServer, NamedPipeTransport};
use wardline_policy::CompiledPolicy;

#[derive(Parser)]
#[command(
    name = "wardline-mcp",
    version,
    about = "Zero-secret MCP stdio JSON-RPC 2.0 adapter, wrapping proxy, and server registry",
    args_conflicts_with_subcommands = true
)]
struct Args {
    #[command(subcommand)]
    command: Option<McpCommand>,

    /// Target hardened Named Pipe / Unix domain socket served by `wardline-guard`.
    #[arg(long, default_value = DEFAULT_PIPE_NAME)]
    pipe: String,

    /// Record least-privilege capabilities observed during this session.
    #[arg(long, default_value_t = false)]
    learn: bool,

    /// Optional baseline policy TOML used to diff --learn suggestions.
    #[arg(long)]
    policy: Option<PathBuf>,

    /// Optional file path where the --learn TOML capability diff will be written on exit.
    #[arg(long)]
    learn_out: Option<PathBuf>,
}

#[derive(Subcommand)]
enum McpCommand {
    /// Serve the native Wardline MCP JSON-RPC 2.0 stdio loop forwarding to wardline-guard.
    Serve {
        #[arg(long, default_value = DEFAULT_PIPE_NAME)]
        pipe: String,
        #[arg(long, default_value_t = false)]
        learn: bool,
        #[arg(long)]
        policy: Option<PathBuf>,
        #[arg(long)]
        learn_out: Option<PathBuf>,
    },
    /// Wrap an arbitrary third-party stdio MCP server inside policy + fail-closed sandbox gating.
    Wrap {
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "schemas/wardline.v1.toml")]
        policy: PathBuf,
        #[arg(long, default_value = "L1")]
        isolation: String,
        #[arg(long, default_value = ".")]
        working_dir: String,
        #[arg(long)]
        allow_tool: Vec<String>,
        #[arg(long, default_value_t = false)]
        learn: bool,
        #[arg(long)]
        learn_out: Option<PathBuf>,
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Manage the local registry of approved MCP servers.
    Servers {
        #[command(subcommand)]
        action: ServersAction,
    },
}

#[derive(Subcommand)]
enum ServersAction {
    Register {
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "wardline-mcp-servers.json")]
        registry: PathBuf,
        #[arg(long)]
        policy: Option<String>,
        #[arg(long, default_value = "L1")]
        isolation: String,
        #[arg(long)]
        allow_tool: Vec<String>,
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    List {
        #[arg(long, default_value = "wardline-mcp-servers.json")]
        registry: PathBuf,
    },
    Check {
        #[arg(long)]
        name: Option<String>,
        #[arg(long, default_value = "wardline-mcp-servers.json")]
        registry: PathBuf,
        #[arg(long)]
        policy: Option<PathBuf>,
    },
}

fn parse_isolation(raw: &str) -> anyhow::Result<IsolationLevel> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "unisolated" | "none" => Ok(IsolationLevel::Unisolated),
        "l0" | "0" => Ok(IsolationLevel::L0),
        "l1" | "1" => Ok(IsolationLevel::L1),
        "l1.5" | "l1_5" | "1.5" => Ok(IsolationLevel::L1_5),
        "l2" | "2" => Ok(IsolationLevel::L2),
        other => anyhow::bail!(
            "unsupported isolation '{other}'; expected unisolated, l0, l1, l1.5, or l2"
        ),
    }
}

fn load_compiled(path: &PathBuf) -> anyhow::Result<CompiledPolicy> {
    let raw = std::fs::read_to_string(path)?;
    Ok(CompiledPolicy::from_toml_str(&raw)?)
}

fn run_serve(
    pipe: String,
    learn: bool,
    policy: Option<PathBuf>,
    learn_out: Option<PathBuf>,
) -> anyhow::Result<()> {
    let transport = NamedPipeTransport::new(pipe);
    let mut server = if learn {
        McpServer::with_learn(transport)
    } else {
        McpServer::new(transport)
    };
    let stdin = std::io::stdin().lock();
    let stdout = std::io::stdout().lock();
    server.run_stdio_loop(stdin, stdout)?;

    if learn {
        let baseline = match policy {
            Some(ref p) => Some(load_compiled(p)?.manifest),
            None => None,
        };
        if let Some(diff) = server.render_learn_diff_toml(baseline.as_ref()) {
            if let Some(out_path) = learn_out {
                std::fs::write(&out_path, diff)?;
            } else {
                eprintln!("{diff}");
            }
        }
    }
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    match args.command {
        None => run_serve(args.pipe, args.learn, args.policy, args.learn_out),
        Some(McpCommand::Serve {
            pipe,
            learn,
            policy,
            learn_out,
        }) => run_serve(pipe, learn, policy, learn_out),
        Some(McpCommand::Wrap {
            name,
            policy,
            isolation,
            working_dir,
            allow_tool,
            learn,
            learn_out,
            command,
        }) => {
            let compiled = load_compiled(&policy)?;
            let isolation = parse_isolation(&isolation)?;
            let baseline_manifest = compiled.manifest.clone();
            let (exe, cmd_args) = command
                .split_first()
                .ok_or_else(|| anyhow::anyhow!("missing wrapped command"))?;
            let cfg = WrapConfig {
                server_name: name,
                command: exe.clone(),
                args: cmd_args.to_vec(),
                working_dir,
                isolation,
                allowed_tools: allow_tool.into_iter().collect::<BTreeSet<_>>(),
                fail_closed_sandbox: isolation != IsolationLevel::Unisolated,
            };
            let mut proxy =
                WrappedMcpProxy::new(cfg, compiled, learn).map_err(|e| anyhow::anyhow!(e))?;
            let stdin = std::io::stdin().lock();
            let stdout = std::io::stdout().lock();
            proxy.run_stdio_proxy(stdin, stdout)?;
            if let Some(rec) = proxy.learn.as_ref() {
                let diff = rec.render_toml_diff(Some(&baseline_manifest));
                if let Some(out_path) = learn_out {
                    std::fs::write(out_path, diff)?;
                } else {
                    eprintln!("{diff}");
                }
            }
            Ok(())
        }
        Some(McpCommand::Servers { action }) => match action {
            ServersAction::Register {
                name,
                registry,
                policy,
                isolation,
                allow_tool,
                command,
            } => {
                let mut reg = McpRegistry::load(&registry).map_err(|e| anyhow::anyhow!(e))?;
                let (exe, cmd_args) = command
                    .split_first()
                    .ok_or_else(|| anyhow::anyhow!("missing server command"))?;
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let entry = McpServerEntry {
                    name,
                    command: exe.clone(),
                    args: cmd_args.to_vec(),
                    allowed_tools: allow_tool,
                    policy_path: policy,
                    sandbox_tier: parse_isolation(&isolation)?,
                    registered_at_unix_secs: now,
                };
                reg.register(entry).map_err(|e| anyhow::anyhow!(e))?;
                reg.save(&registry).map_err(|e| anyhow::anyhow!(e))?;
                println!("{}", serde_json::to_string_pretty(&reg)?);
                Ok(())
            }
            ServersAction::List { registry } => {
                let reg = McpRegistry::load(&registry).map_err(|e| anyhow::anyhow!(e))?;
                println!("{}", serde_json::to_string_pretty(&reg)?);
                Ok(())
            }
            ServersAction::Check {
                name,
                registry,
                policy,
            } => {
                let reg = McpRegistry::load(&registry).map_err(|e| anyhow::anyhow!(e))?;
                let compiled = match policy {
                    Some(ref p) => Some(load_compiled(p)?),
                    None => None,
                };
                let mut reports = Vec::new();
                for entry in reg.list() {
                    if name.as_ref().is_some_and(|n| n != &entry.name) {
                        continue;
                    }
                    reports.push(check_server_entry(entry, compiled.as_ref()));
                }
                let all_ok = reports.iter().all(|r| r.ok);
                println!("{}", serde_json::to_string_pretty(&reports)?);
                if !all_ok {
                    std::process::exit(1);
                }
                Ok(())
            }
        },
    }
}
