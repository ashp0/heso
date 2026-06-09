//! `heso-verify-cli` — the STANDALONE ActionReceipt verifier.
//!
//! The dependency-light binary a relying party runs with **zero heso install**:
//! it is vendored into an evidence bundle (see `heso-engine bundle`) and
//! invoked by the bundle's `VERIFY.sh`. It reads the chained receipts and the
//! pinned operator public key, reuses [`heso_action`]'s offline verify path
//! VERBATIM (the same code the engine's `verify` subcommand runs), and reports a
//! verdict with a stable contract:
//!
//! ```text
//! heso-verify-cli [--json] <receipts.jsonl> <public_key_file>
//!
//! EXIT CODES (stable):
//!   0   VALID         — every receipt verifies; for >1, the chain is intact
//!   1   INVALID       — tamper / bad signature / broken chain link
//!   2   WRONG ALG/HASH— foreign or older alg, unsupported version, malformed,
//!                       or a content action_hash mismatch
//!   64  USAGE         — bad command line / unreadable inputs (EX_USAGE)
//! ```
//!
//! With `--json`, a single compact object is printed to stdout with a fixed key
//! order (`status`, `exit_code`, `total`, `reason`, `failed_at`, `failure_kind`,
//! `diverged_field`) and the PINPOINT of a broken link
//! ("chain broken at receipt K of N", the diverged field). Without it, a single
//! human line is printed (stdout on success, stderr on failure).

mod verifier;

use std::process::ExitCode as ProcExit;

use verifier::{parse_receipts_jsonl, validate_pubkey, verify_chain_verdict, ExitCode, Verdict};

fn main() -> ProcExit {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "-h" || a == "--help" || a == "help") {
        print_usage();
        return ProcExit::SUCCESS;
    }
    match run(&args) {
        Ok((verdict, json)) => emit(&verdict, json, true),
        Err((verdict, json)) => emit(&verdict, json, false),
    }
}

/// Parse argv, read the inputs, and produce the [`Verdict`]. Returns `Ok` for a
/// VALID verdict and `Err` for any non-zero one, both carrying the `--json` flag,
/// so `main` can route stdout/stderr correctly while keeping the exit-code
/// mapping in one place ([`emit`]).
#[allow(clippy::type_complexity)]
fn run(args: &[String]) -> Result<(Verdict, bool), (Verdict, bool)> {
    // --- argv (no clap) -----------------------------------------------------
    let mut json = false;
    let mut positionals: Vec<&str> = Vec::new();
    let mut signature_path: Option<&str> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => json = true,
            // -h / --help / help are intercepted in `main` before `run`.
            "--signature" | "--sig" => {
                i += 1;
                match args.get(i) {
                    Some(p) => signature_path = Some(p.as_str()),
                    None => return Err((usage("--signature needs a path argument"), json)),
                }
            }
            other if other.starts_with('-') => {
                return Err((usage(&format!("unknown flag `{other}`")), json));
            }
            other => positionals.push(other),
        }
        i += 1;
    }

    let (receipts_path, pubkey_path) = match positionals.as_slice() {
        [r, p] => (*r, *p),
        _ => {
            return Err((
                usage("expected <receipts.jsonl> <public_key_file> [--json] [--signature <file>]"),
                json,
            ))
        }
    };

    // --- read + validate inputs (failures are USAGE, exit 64) ---------------
    let receipts_bytes = match std::fs::read(receipts_path) {
        Ok(b) => b,
        Err(e) => return Err((usage(&format!("reading {receipts_path}: {e}")), json)),
    };
    let pubkey_raw = match std::fs::read_to_string(pubkey_path) {
        Ok(s) => s,
        Err(e) => return Err((usage(&format!("reading {pubkey_path}: {e}")), json)),
    };
    let pubkey = pubkey_raw.trim().to_string();
    if let Err(v) = validate_pubkey(&pubkey) {
        return Err((v, json));
    }

    // The detached signature is OPTIONAL evidence over receipts.jsonl. v1 of the
    // bundle records it but the per-receipt operator signatures are the
    // load-bearing trust; we acknowledge a provided sig file is readable (so a
    // missing/garbled one is a loud usage error) without inventing a second trust
    // root the format does not yet define.
    if let Some(sig) = signature_path {
        if let Err(e) = std::fs::read(sig) {
            return Err((usage(&format!("reading signature {sig}: {e}")), json));
        }
    }

    let chain = match parse_receipts_jsonl(&receipts_bytes) {
        Ok(c) => c,
        Err(v) => return Err((v, json)),
    };

    let verdict = verify_chain_verdict(&chain, Some(&pubkey));
    if verdict.code == ExitCode::Valid {
        Ok((verdict, json))
    } else {
        Err((verdict, json))
    }
}

/// Print the verdict in the requested form and return the contract exit code.
/// On success the line goes to stdout; on failure to stderr — but `--json`
/// always goes to stdout (a script captures it) regardless of pass/fail.
fn emit(verdict: &Verdict, json: bool, ok: bool) -> ProcExit {
    if json {
        println!("{}", verdict.to_json());
    } else if ok {
        println!("{}", verdict.human());
    } else {
        eprintln!("{}", verdict.human());
    }
    ProcExit::from(verdict.code as u8)
}

fn usage(msg: &str) -> Verdict {
    Verdict {
        code: ExitCode::Usage,
        reason: msg.to_string(),
        total: 0,
        failed_at: None,
        failure_kind: Some("usage"),
        diverged_field: None,
    }
}

fn print_usage() {
    eprintln!(
        "heso-verify-cli — offline ActionReceipt / chain verifier (zero heso install)\n\n\
         USAGE:\n  \
         heso-verify-cli [--json] <receipts.jsonl> <public_key_file> [--signature <file>]\n\n\
         EXIT CODES:\n  \
         0   valid                    every receipt verifies; chain intact\n  \
         1   invalid                  tamper / bad signature / broken chain link\n  \
         2   wrong algorithm or hash  foreign/older alg, unsupported version, malformed, hash mismatch\n  \
         64  usage                    bad arguments or unreadable inputs"
    );
}
