//! The two break-glass operations an operator has to perform by hand.
//!
//! They are here because the alternative is a runbook that says «подпись —
//! Ed25519 над BREAK-GLASS-доменом» and leaves the person at 03:00 to write
//! the code. A mechanism whose only client is a program nobody has written is
//! not shipped; it is described.
//!
//! Two, and only two:
//!
//!  * [`sign_grant`] — check the grant against every invariant *first*, then
//!    sign it. The order is the point: an over-long window, a missing ticket or
//!    a scope this build does not honour is refused at the keyboard, where it
//!    costs a retype, rather than in the webhook's poll loop, where it costs a
//!    journal entry saying `rejected` and an operator wondering why the glass
//!    did not break.
//!  * [`verify_journal`] — walk somebody's journal file and say whether the
//!    chain holds. Without it the tamper-evidence claim is a property nobody
//!    can check: the incident review that needs it is the one case where the
//!    person reading the file is not the person who wrote it.
//!
//! What is deliberately not here: key generation. `gen-webhook-pki` issues a
//! serving certificate because nothing else in this tree can, and a
//! break-glass key is the opposite case — it must be issued by the directory
//! that also revokes it when its holder leaves, and a key minted by this
//! binary would have no such directory behind it. `sign-break-glass` prints the
//! public key of the seed it was given, which is the trust root the cluster
//! pins, so an operator never has to derive it themselves.

use std::fs;
use std::path::Path;

use anyhow::{bail, Context, Result};
use ferrum_breakglass::{check_invariants, Entry, Grant, Journal, JOURNAL_SCHEMA};

/// `ferrumctl sign-break-glass <grant.json> --key <seedfile> -o <grant.sig>`.
///
/// Writes the signature as lowercase hex, which is the form the webhook's mount
/// carries and the form a `kubectl create secret --from-file` produces without
/// anybody thinking about encodings.
pub fn sign_grant(input: &Path, key: &Path, output: &Path) -> Result<()> {
    let raw = fs::read(input).with_context(|| format!("read {}", input.display()))?;
    let grant: Grant = serde_json::from_slice(&raw)
        .with_context(|| format!("{} is not a break-glass grant", input.display()))?;
    // Before the signature, never after. A grant that cannot be honoured must
    // fail here rather than in the cluster.
    check_invariants(&grant).map_err(anyhow::Error::from)?;
    if grant.expires_at <= chrono::Utc::now() {
        bail!(
            "grant {} expires at {}, which is in the past: signing it would produce a document \
             the webhook refuses on sight",
            grant.id,
            grant.expires_at
        );
    }

    let secret = read_secret_key(key)?;
    let public_key = ferrum_crypto::public_key_from_secret(&secret).map_err(anyhow::Error::from)?;
    let signature = ferrum_crypto::sign_break_glass(&raw, &secret).map_err(anyhow::Error::from)?;
    fs::write(output, hex(&signature)).with_context(|| format!("write {}", output.display()))?;

    println!("signed: {}", output.display());
    println!("  grant     {} scope={}", grant.id, grant.scope);
    println!("  subject   {}", grant.subject);
    println!("  issuer    {}", grant.issuer);
    println!("  ticket    {}", grant.ticket);
    println!(
        "  window    {} .. {} ({} minutes)",
        grant.issued_at,
        grant.expires_at,
        (grant.expires_at - grant.issued_at).num_minutes()
    );
    // The trust root the cluster has to be armed with. Printed every time so
    // an operator never derives it by hand and never pins the wrong one.
    println!("  trustRoot {}", hex(&public_key));
    Ok(())
}

/// `ferrumctl verify-journal <break-glass.jsonl>`.
///
/// Prints each chain, one line per entry, with its head. The head is the value
/// to compare against whatever copy was kept off the node — the container log
/// or `ferrum_admission_break_glass_journal_info` — because a chain verifies
/// against itself even when it was rewritten from scratch.
///
/// **One file, possibly several chains.** Each replica keeps its own: the
/// journal is written per process and starts at genesis when that process
/// starts, so the obvious way to collect one — `kubectl logs -l
/// app.kubernetes.io/name=ferrum-admission` — returns two interleaved chains on
/// a two-replica install. Verifying that as one sequence fails with «seq 0
/// where 1 was expected», which reads as *an entry is missing* and sends an
/// operator looking for tampering in the middle of an incident. It is not: it
/// is two chains in one file, and `component` says which is which. So this
/// groups by `component` first and verifies each group on its own. Found by
/// running the shipped procedure against a live two-replica install rather than
/// by reasoning about it.
pub fn verify_journal(input: &Path) -> Result<()> {
    let text = fs::read_to_string(input).with_context(|| format!("read {}", input.display()))?;
    let lines: Vec<String> = text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(str::to_string)
        .collect();
    if lines.is_empty() {
        println!(
            "{}: empty chain, nothing was ever recorded",
            input.display()
        );
        return Ok(());
    }

    // Group by writer, first-seen order, so the output reads in the order the
    // replicas appear in the file rather than alphabetically.
    let mut order: Vec<String> = Vec::new();
    let mut chains: std::collections::BTreeMap<String, Vec<String>> = Default::default();
    for (n, line) in lines.iter().enumerate() {
        let entry: Entry = serde_json::from_str(line)
            .with_context(|| format!("{}:{}: not a journal entry", input.display(), n + 1))?;
        if entry.schema != JOURNAL_SCHEMA {
            bail!(
                "{}:{}: schema {:?} is not {JOURNAL_SCHEMA}",
                input.display(),
                n + 1,
                entry.schema
            );
        }
        if !chains.contains_key(&entry.component) {
            order.push(entry.component.clone());
        }
        chains
            .entry(entry.component)
            .or_default()
            .push(line.clone());
    }

    if order.len() > 1 {
        println!(
            "{} chains in this file, one per writer. Each is verified on its own: a journal is \
             per process and every one of them starts at genesis.\n",
            order.len()
        );
    }
    for component in &order {
        let group = chains.get(component).expect("grouped");
        let entries = Journal::verify_lines(group)
            .map_err(anyhow::Error::from)
            .with_context(|| format!("chain of {component}"))?;
        println!("chain: {component}");
        for entry in &entries {
            let window = match (entry.issued_at, entry.expires_at) {
                (Some(from), Some(to)) => format!(" window={from}..{to}"),
                _ => String::new(),
            };
            println!(
                "{:>4}  {}  {:<9} grant={} subject={} ticket={}{}{}",
                entry.seq,
                entry.ts,
                entry.event,
                dash(&entry.grant_id),
                dash(&entry.subject),
                dash(&entry.ticket),
                window,
                if entry.detail.is_empty() {
                    String::new()
                } else {
                    format!(" — {}", entry.detail)
                },
            );
        }
        println!(
            "  verified: {} entries, head {}\n",
            entries.len(),
            entries.last().expect("non-empty").hash
        );
    }
    println!(
        "Compare each head against the copy kept off the node (the container log, or the `head` \
         label of ferrum_admission_break_glass_journal_info on that replica). A chain rewritten \
         from scratch verifies too, and so does one with its tail cut off; only an older head \
         can tell you either happened."
    );
    Ok(())
}

fn dash(value: &str) -> &str {
    if value.is_empty() {
        "-"
    } else {
        value
    }
}

fn read_secret_key(path: &Path) -> Result<Vec<u8>> {
    let text = fs::read_to_string(path).with_context(|| format!("read key {}", path.display()))?;
    let secret = crate::fsig::hex_decode(&text)?;
    if secret.len() != ferrum_crypto::ED25519_SECRET_KEY_LEN {
        bail!(
            "key file must hold {} hex bytes, got {}",
            ferrum_crypto::ED25519_SECRET_KEY_LEN,
            secret.len()
        );
    }
    Ok(secret)
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}
