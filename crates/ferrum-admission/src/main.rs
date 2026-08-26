//! Offline evaluator for a compiled FADM program and a JSON subject.
//! HTTP webhook serving is a follow-up; this binary is not a compiler.

#![deny(unsafe_code)]

use ferrum_admission::{admit_bytes, AdmissionSubject};
use std::process::exit;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: ferrum-admission <program.fadm> <subject.json>");
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
