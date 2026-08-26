//! Admission webhook and offline FADM evaluator. Not a compiler.

#![deny(unsafe_code)]

use ferrum_admission::{
    admit_bytes, load_bundle, load_tls_config, parse_trust_root, serve, AdmissionSubject,
    ReviewConfig, WebhookState,
};
use ferrum_api::PolicyExceptionSpec;
use std::collections::BTreeMap;
use std::process::exit;
use std::sync::Arc;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("review") => cmd_review(&args[2..]),
        Some("serve") => cmd_serve(&args[2..]),
        _ => cmd_eval(&args),
    }
}

fn cmd_eval(args: &[String]) {
    if args.len() != 3 {
        eprintln!("usage: ferrum-admission <program.fadm> <subject.json>");
        eprintln!("       ferrum-admission review --bundle <fsig> --trust-root <32-byte-hex> [--exceptions <json> --policy-name <name>] <admissionreview.json>");
        eprintln!("       ferrum-admission serve --listen 127.0.0.1:8443 --bundle <fsig> --trust-root <32-byte-hex> [--tls-cert --tls-key]");
        eprintln!("missing or invalid compiled program denies the request (fail closed)");
        exit(2);
    }

    let program = match std::fs::read(&args[1]) {
        Ok(bytes) => bytes,
        Err(err) => {
            eprintln!("error: read {}: {err}", args[1]);
            exit(2);
        }
    };
    let subject_raw = match std::fs::read_to_string(&args[2]) {
        Ok(text) => text,
        Err(err) => {
            eprintln!("error: read {}: {err}", args[2]);
            exit(2);
        }
    };
    let subject: AdmissionSubject = match serde_json::from_str(&subject_raw) {
        Ok(subject) => subject,
        Err(err) => {
            eprintln!("error: subject json: {err}");
            exit(2);
        }
    };

    let decision = admit_bytes(&program, &subject, &[], chrono::Utc::now());
    match serde_json::to_string_pretty(&decision) {
        Ok(json) => println!("{json}"),
        Err(err) => {
            eprintln!("error: encode decision: {err}");
            exit(2);
        }
    }
    if decision.allowed {
        exit(0);
    }
    exit(1);
}

fn cmd_review(args: &[String]) {
    let flags = parse_flags(args);
    let bundle_path = require_flag(&flags, "bundle");
    let trust_hex = require_flag(&flags, "trust-root");
    let review_path = flags.positional.first().cloned().unwrap_or_else(|| {
        die("usage: review --bundle <fsig> --trust-root <hex> <admissionreview.json>")
    });

    let trust_root = match parse_trust_root(&trust_hex) {
        Ok(k) => k,
        Err(err) => {
            eprintln!("error: trust-root: {err}");
            exit(2);
        }
    };
    let bundle = read_file(&bundle_path);
    let program = match load_bundle(&bundle, &trust_root) {
        Ok(p) => p,
        Err(err) => {
            eprintln!("error: bundle: {err}");
            exit(2);
        }
    };
    let (exceptions, cfg) = exceptions_and_config(&flags);
    let body = read_file(&review_path);
    let reply = cfg.handle_bytes(&body, Some(&program), &exceptions, chrono::Utc::now());
    match serde_json::from_slice::<serde_json::Value>(&reply.body) {
        Ok(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default()),
        Err(_) => {
            let _ = std::io::Write::write_all(&mut std::io::stdout(), &reply.body);
        }
    }
    let allowed = reply.status == 200
        && serde_json::from_slice::<serde_json::Value>(&reply.body)
            .ok()
            .and_then(|v| v["response"]["allowed"].as_bool())
            .unwrap_or(false);
    if allowed {
        exit(0);
    }
    exit(1);
}

fn cmd_serve(args: &[String]) {
    let flags = parse_flags(args);
    let bundle_path = require_flag(&flags, "bundle");
    let trust_hex = require_flag(&flags, "trust-root");
    let listen = flags
        .map
        .get("listen")
        .cloned()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "127.0.0.1:8443".into());

    let trust_root = match parse_trust_root(&trust_hex) {
        Ok(k) => k,
        Err(err) => {
            eprintln!("error: trust-root: {err}");
            exit(2);
        }
    };
    let bundle = read_file(&bundle_path);
    let program = match load_bundle(&bundle, &trust_root) {
        Ok(p) => p,
        Err(err) => {
            eprintln!("error: bundle: {err}");
            exit(2);
        }
    };
    let (exceptions, cfg) = exceptions_and_config(&flags);
    let tls = match (flags.map.get("tls-cert"), flags.map.get("tls-key")) {
        (Some(cert), Some(key)) if !cert.is_empty() && !key.is_empty() => {
            match load_tls_config(cert, key) {
                Ok(cfg) => Some(cfg),
                Err(err) => {
                    eprintln!("error: tls: {err}");
                    exit(2);
                }
            }
        }
        (None, None) => None,
        _ => {
            eprintln!("error: --tls-cert and --tls-key must be provided together");
            exit(2);
        }
    };

    let state = Arc::new(WebhookState {
        program,
        exceptions,
        config: cfg,
    });
    eprintln!("ferrum-admission listening on {listen}");
    if let Err(err) = serve(&listen, state, tls) {
        eprintln!("error: serve: {err}");
        exit(2);
    }
}

struct Flags {
    map: BTreeMap<String, String>,
    positional: Vec<String>,
}

fn parse_flags(args: &[String]) -> Flags {
    let mut map = BTreeMap::new();
    let mut positional = Vec::new();
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
        } else {
            positional.push(a.clone());
        }
        i += 1;
    }
    Flags { map, positional }
}

fn require_flag(flags: &Flags, name: &str) -> String {
    match flags.map.get(name) {
        Some(v) if !v.is_empty() => v.clone(),
        _ => die(&format!("missing --{name}")),
    }
}

fn review_config(flags: &Flags) -> ReviewConfig {
    ReviewConfig {
        policy_name: flags.map.get("policy-name").cloned().unwrap_or_default(),
        policy_namespace: flags
            .map
            .get("policy-namespace")
            .cloned()
            .unwrap_or_default(),
    }
}

fn exceptions_and_config(flags: &Flags) -> (Vec<PolicyExceptionSpec>, ReviewConfig) {
    let exceptions = load_exceptions(flags.map.get("exceptions"));
    let cfg = review_config(flags);
    if !exceptions.is_empty() && cfg.policy_name.is_empty() {
        die("--policy-name is required when --exceptions is set");
    }
    (exceptions, cfg)
}

fn load_exceptions(path: Option<&String>) -> Vec<PolicyExceptionSpec> {
    let Some(path) = path else {
        return Vec::new();
    };
    if path.is_empty() {
        return Vec::new();
    }
    let raw = read_file(path);
    if let Ok(list) = serde_json::from_slice::<Vec<PolicyExceptionSpec>>(&raw) {
        return list;
    }
    match serde_json::from_slice::<PolicyExceptionSpec>(&raw) {
        Ok(one) => vec![one],
        Err(err) => {
            eprintln!("error: exceptions json: {err}");
            exit(2);
        }
    }
}

fn read_file(path: &str) -> Vec<u8> {
    match std::fs::read(path) {
        Ok(b) => b,
        Err(err) => {
            eprintln!("error: read {path}: {err}");
            exit(2);
        }
    }
}

fn die(msg: &str) -> ! {
    eprintln!("error: {msg}");
    exit(2);
}
