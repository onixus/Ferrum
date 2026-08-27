//! Node agent. Last-known-good bundle, never fail-open if CP dies.

use ferrum_agent::{parse_trust_root, poll_bundle, Agent, AgentConfig, AgentRole};
use ferrum_common::FerrumError;
use ferrum_export::{RotatingFileSink, SinkContext};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::exit;
use std::time::Duration;

const DEFAULT_EXPORT_MAX_BYTES: u64 = 64 * 1024 * 1024;
const DEFAULT_EXPORT_KEEP: usize = 5;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let flags = parse_flags(&args);
    let trust_hex = require_flag(&flags, "trust-root");
    let trust_root = match parse_trust_root(&trust_hex) {
        Ok(k) => k,
        Err(err) => {
            eprintln!("ferrum-agent: trust-root: {err}");
            exit(2);
        }
    };

    let role = match flags.map.get("role") {
        Some(s) if !s.is_empty() => match AgentRole::parse_name(s) {
            Ok(r) => r,
            Err(err) => {
                eprintln!("ferrum-agent: {err}");
                exit(2);
            }
        },
        _ => AgentRole::Observe,
    };

    let reload_ms: u64 = match flags.map.get("reload-ms") {
        Some(s) if !s.is_empty() => s.parse().unwrap_or_else(|_| die("invalid --reload-ms")),
        _ => 1000,
    };

    let bundle_path = flags
        .map
        .get("bundle")
        .cloned()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from);
    let lkg_dir = flags
        .map
        .get("lkg-dir")
        .cloned()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from);

    let policy_name = flags.map.get("policy-name").cloned().unwrap_or_default();

    let export_dir = flags
        .map
        .get("export-dir")
        .cloned()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from);
    let export_max_bytes: u64 = match flags.map.get("export-max-bytes") {
        Some(s) if !s.is_empty() => s
            .parse()
            .unwrap_or_else(|_| die("invalid --export-max-bytes")),
        _ => DEFAULT_EXPORT_MAX_BYTES,
    };
    let export_keep: usize = match flags.map.get("export-keep") {
        Some(s) if !s.is_empty() => s.parse().unwrap_or_else(|_| die("invalid --export-keep")),
        _ => DEFAULT_EXPORT_KEEP,
    };
    let node = flags
        .map
        .get("node")
        .cloned()
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("HOSTNAME").ok().filter(|s| !s.is_empty()))
        .unwrap_or_else(|| "unknown-node".into());

    let mut agent = Agent::new(AgentConfig {
        role,
        lkg_dir,
        trust_root,
        bundle_path: bundle_path.clone(),
        exceptions: Vec::new(),
        policy_name,
    });

    if let Err(err) = agent.restore_last_known_good() {
        eprintln!("ferrum-agent: {err}");
    }

    if let Some(path) = bundle_path.as_ref() {
        if let Err(err) = agent.apply_path(path) {
            eprintln!("ferrum-agent: {err}");
            if !agent.using_last_known_good() {
                exit(2);
            }
        }
        if let Err(err) = agent.reload_exceptions_path(path) {
            eprintln!("ferrum-agent: exceptions load failed, waivers dropped: {err}");
        }
    }

    match agent.attach_pins() {
        Ok(()) => {}
        Err(FerrumError::Degraded(reason)) => {
            eprintln!("ferrum-agent: {reason}");
        }
        Err(err) => {
            eprintln!("ferrum-agent: {err}");
        }
    }

    // The sink is the future event destination once the datapath pumps; today
    // it pins down the export contract (node/role stamped, digest/degraded
    // refreshed by the poll loop) without touching kernel attach.
    let export_sink = export_dir.map(|dir| {
        let role_name = if role.respond_enabled() {
            "respond"
        } else {
            "observe"
        };
        let sink = RotatingFileSink::new(
            dir,
            export_max_bytes,
            export_keep,
            SinkContext::new(node, role_name),
        );
        sink.set_bundle_digest(agent.last_good_digest().cloned());
        sink.set_degraded(agent.is_degraded());
        sink
    });
    let export_ctx = export_sink.as_ref().map(RotatingFileSink::context);

    if let Some(path) = bundle_path {
        poll_bundle(
            &mut agent,
            &path,
            Duration::from_millis(reload_ms),
            export_ctx,
        );
    }
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}

struct Flags {
    map: BTreeMap<String, String>,
}

fn parse_flags(args: &[String]) -> Flags {
    let mut map = BTreeMap::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if let Some(rest) = a.strip_prefix("--") {
            if let Some((k, v)) = rest.split_once('=') {
                map.insert(k.to_string(), v.to_string());
            } else if let Some(val) = args.get(i + 1) {
                if val.starts_with("--") {
                    map.insert(rest.to_string(), String::new());
                } else {
                    map.insert(rest.to_string(), val.clone());
                    i += 1;
                }
            } else {
                map.insert(rest.to_string(), String::new());
            }
        }
        i += 1;
    }
    Flags { map }
}

fn require_flag(flags: &Flags, name: &str) -> String {
    match flags.map.get(name) {
        Some(v) if !v.is_empty() => v.clone(),
        _ => die(
            "usage: ferrum-agent --trust-root <32-byte-hex> [--bundle <fsig|dir>] [--lkg-dir <dir>] [--role observe|respond] [--policy-name <name>] [--reload-ms 1000] [--node <name>] [--export-dir <dir>] [--export-max-bytes 67108864] [--export-keep 5]",
        ),
    }
}

fn die(msg: &str) -> ! {
    eprintln!("ferrum-agent: {msg}");
    exit(2);
}
