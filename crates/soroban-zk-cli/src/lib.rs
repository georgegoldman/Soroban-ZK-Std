//! `soroban-zk`: developer CLI for Soroban-ZK-Std.
//!
//! Commands:
//!
//! * `import-vk` turns a SnarkJS or gnark Groth16 verifying key (BN254) into
//!   `no_std`, allocation-free Rust constants for `soroban_zk_std::groth16`.
//! * `encode-proof` turns a SnarkJS `proof.json` + `public.json` into the
//!   256-byte buffer `Groth16Proof::from_bytes` expects plus 32-byte scalars.
//! * `inspect` checks a key, proof or public-input file offline.
//!
//! This is a host-side tool, so it uses `std`. It never panics on bad input:
//! every failure is a [`CliError`] with a message and a non-zero exit code.

pub mod bn254;
pub mod codegen;
pub mod formats;

use core::fmt;
use std::{fs, io, io::Write as _, process::ExitCode};

use serde_json::Value;

use crate::formats::{Kind, VkFormat};

/// Exit code for an invalid artifact or I/O failure.
pub const EXIT_FAILURE: u8 = 1;
/// Exit code for bad command-line usage.
pub const EXIT_USAGE: u8 = 2;

/// A user-facing error with its process exit code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliError {
    pub message: String,
    pub code: u8,
}

impl CliError {
    pub fn failure(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            code: EXIT_FAILURE,
        }
    }

    pub fn usage(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            code: EXIT_USAGE,
        }
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

pub const USAGE: &str = "\
soroban-zk: Groth16 / BN254 tooling for Soroban-ZK-Std

USAGE:
    soroban-zk <COMMAND> [OPTIONS]
    cargo soroban-zk <COMMAND> [OPTIONS]

COMMANDS:
    import-vk     Generate const Rust definitions from a verifying key
                    --input <FILE>             verification key JSON (required)
                    --format <snarkjs|gnark>   input format (default: snarkjs)
                    --out <FILE>               output .rs file (default: stdout)
                    --name <IDENT>             constant name (default: VERIFYING_KEY)
    encode-proof  Encode a SnarkJS proof and public inputs to bytes
                    --proof <FILE>             proof.json (required)
                    --public <FILE>            public.json (optional)
                    --output <hex|json|stellar-cli>   (default: hex)
                    --proof-arg <NAME>         stellar-cli proof flag (default: proof_bytes)
                    --public-arg <NAME>        stellar-cli inputs flag (default: public_inputs_bytes)
    inspect       Check a key, proof, public.json or hex proof file offline
                    <FILE>

Only BN254 Groth16 artifacts are supported (no BLS12-381, no Noir yet).
";

/// The outcome of a successful command: text for stdout.
pub type Output = String;

/// Runs the CLI with `args` (excluding the program name).
pub fn run(args: &[String]) -> Result<Output, CliError> {
    let Some((cmd, rest)) = args.split_first() else {
        return Err(CliError::usage(format!("missing command\n\n{USAGE}")));
    };
    match cmd.as_str() {
        "-h" | "--help" | "help" => Ok(USAGE.to_string()),
        "-V" | "--version" => Ok(format!("soroban-zk {}\n", env!("CARGO_PKG_VERSION"))),
        "import-vk" => import_vk(&Opts::parse(
            rest,
            &["input", "format", "out", "name"],
            false,
        )?),
        "encode-proof" => encode_proof(&Opts::parse(
            rest,
            &["proof", "public", "output", "proof-arg", "public-arg"],
            false,
        )?),
        "inspect" => inspect(&Opts::parse(rest, &[], true)?),
        other => Err(CliError::usage(format!(
            "unknown command `{other}`\n\n{USAGE}"
        ))),
    }
}

/// Strips the leading `soroban-zk` argument cargo passes to subcommands
/// (`cargo soroban-zk x` runs `cargo-soroban-zk soroban-zk x`).
pub fn strip_cargo_subcommand(mut args: Vec<String>) -> Vec<String> {
    if args.first().map(String::as_str) == Some("soroban-zk") {
        args.remove(0);
    }
    args
}

/// Parsed `--key value` options plus positional arguments.
#[derive(Debug, Default)]
struct Opts {
    pairs: Vec<(String, String)>,
    positional: Vec<String>,
}

impl Opts {
    fn parse(args: &[String], allowed: &[&str], positional: bool) -> Result<Self, CliError> {
        let mut out = Opts::default();
        let mut it = args.iter();
        while let Some(a) = it.next() {
            if let Some(flag) = a.strip_prefix("--") {
                let (key, value) = match flag.split_once('=') {
                    Some((k, v)) => (k.to_string(), v.to_string()),
                    None => {
                        let v = it
                            .next()
                            .ok_or_else(|| CliError::usage(format!("--{flag} needs a value")))?;
                        (flag.to_string(), v.clone())
                    }
                };
                if !allowed.contains(&key.as_str()) {
                    return Err(CliError::usage(format!(
                        "unknown option `--{key}`\n\n{USAGE}"
                    )));
                }
                if out.get(&key).is_some() {
                    return Err(CliError::usage(format!("--{key} given more than once")));
                }
                out.pairs.push((key, value));
            } else if positional && !a.starts_with('-') {
                out.positional.push(a.clone());
            } else {
                return Err(CliError::usage(format!(
                    "unexpected argument `{a}`\n\n{USAGE}"
                )));
            }
        }
        Ok(out)
    }

    fn get(&self, key: &str) -> Option<&str> {
        self.pairs
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    fn require(&self, key: &str) -> Result<&str, CliError> {
        self.get(key)
            .ok_or_else(|| CliError::usage(format!("missing required option --{key}")))
    }
}

fn read(path: &str) -> Result<String, CliError> {
    fs::read_to_string(path).map_err(|e| CliError::failure(format!("cannot read `{path}`: {e}")))
}

fn read_json(path: &str) -> Result<Value, CliError> {
    let text = read(path)?;
    serde_json::from_str(&text)
        .map_err(|e| CliError::failure(format!("`{path}` is not valid JSON: {e}")))
}

fn in_file(path: &str) -> impl Fn(String) -> CliError + '_ {
    move |m| CliError::failure(format!("{path}: {m}"))
}

fn import_vk(o: &Opts) -> Result<Output, CliError> {
    let input = o.require("input")?;
    let format = VkFormat::parse(o.get("format").unwrap_or("snarkjs")).map_err(CliError::usage)?;
    let name = o.get("name").unwrap_or("VERIFYING_KEY");
    codegen::validate_const_name(name).map_err(CliError::usage)?;
    let json = read_json(input)?;
    let vk = formats::parse_vk(&json, format).map_err(in_file(input))?;
    let src = codegen::render_vk(&vk, format, name);
    match o.get("out") {
        Some(out) => {
            let mut f = fs::File::create(out)
                .map_err(|e| CliError::failure(format!("cannot create `{out}`: {e}")))?;
            f.write_all(src.as_bytes())
                .map_err(|e| CliError::failure(format!("cannot write `{out}`: {e}")))?;
            Ok(format!(
                "wrote {out}: Groth16 verifying key with {} public input(s) ({} IC points)\n",
                vk.ic.len() - 1,
                vk.ic.len()
            ))
        }
        None => Ok(src),
    }
}

fn encode_proof(o: &Opts) -> Result<Output, CliError> {
    let proof_path = o.require("proof")?;
    let mode = o.get("output").unwrap_or("hex");
    if !matches!(mode, "hex" | "json" | "stellar-cli") {
        return Err(CliError::usage(format!(
            "unknown --output `{mode}` (expected hex, json or stellar-cli)"
        )));
    }
    let proof_arg = o.get("proof-arg").unwrap_or("proof_bytes");
    let public_arg = o.get("public-arg").unwrap_or("public_inputs_bytes");
    for a in [proof_arg, public_arg] {
        if a.is_empty()
            || !a
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err(CliError::usage(format!("invalid argument name `{a}`")));
        }
    }

    let proof =
        formats::parse_snarkjs_proof(&read_json(proof_path)?).map_err(in_file(proof_path))?;
    let inputs = match o.get("public") {
        Some(p) => formats::parse_public_inputs(&read_json(p)?).map_err(in_file(p))?,
        None => Vec::new(),
    };

    let proof_hex = bn254::encode_hex(&proof.to_bytes());
    let input_hex: Vec<String> = inputs.iter().map(|s| bn254::encode_hex(s)).collect();
    let all_inputs = input_hex.concat();

    Ok(match mode {
        "hex" => {
            let mut s = format!("proof ({} bytes): {proof_hex}\n", 256);
            for (i, h) in input_hex.iter().enumerate() {
                s.push_str(&format!("public[{i}] (32 bytes): {h}\n"));
            }
            s.push_str(&format!(
                "public inputs, concatenated ({} bytes): {all_inputs}\n",
                32 * inputs.len()
            ));
            s
        }
        "json" => {
            let v = serde_json::json!({
                "proof": proof_hex,
                "public_inputs": input_hex,
                "public_inputs_concat": all_inputs,
            });
            let mut s = serde_json::to_string_pretty(&v)
                .map_err(|e| CliError::failure(format!("cannot serialise JSON: {e}")))?;
            s.push('\n');
            s
        }
        _ => {
            let mut s = format!("--{proof_arg} {proof_hex}");
            if o.get("public").is_some() {
                s.push_str(&format!(" --{public_arg} {all_inputs}"));
            }
            s.push('\n');
            s
        }
    })
}

fn inspect(o: &Opts) -> Result<Output, CliError> {
    let [path] = o.positional.as_slice() else {
        return Err(CliError::usage(format!(
            "inspect takes exactly one file\n\n{USAGE}"
        )));
    };
    let text = read(path)?;
    let mut report = format!("file: {path}\n");
    let mut problems = Vec::new();

    match serde_json::from_str::<Value>(&text) {
        Ok(json) => {
            let kind = formats::detect(&json).map_err(in_file(path))?;
            report.push_str(&format!("type: {}\n", kind.describe()));
            match kind {
                Kind::SnarkjsVk | Kind::GnarkVk => {
                    let format = if kind == Kind::SnarkjsVk {
                        VkFormat::Snarkjs
                    } else {
                        VkFormat::Gnark
                    };
                    let points = formats::vk_points(&json, format).map_err(in_file(path))?;
                    for (name, p) in &points {
                        let what = match p {
                            formats::PointRef::G1(_) => "G1: on curve",
                            formats::PointRef::G2(_) => "G2: on curve, in prime-order subgroup",
                        };
                        match formats::check_point(name, p, format) {
                            Ok(()) => ok(format!("{name} ({what})"), &mut report),
                            Err(e) => problems.push(e),
                        }
                    }
                    if problems.is_empty() {
                        if let Err(e) = formats::parse_vk(&json, format) {
                            problems.push(e);
                        } else {
                            let n = points
                                .iter()
                                .filter(|(n, _)| n.starts_with("IC[") || n.starts_with("G1.K["))
                                .count();
                            ok(
                                format!("public inputs: {}", n.saturating_sub(1)),
                                &mut report,
                            );
                        }
                    }
                }
                Kind::SnarkjsProof => {
                    let m = json.as_object();
                    for (key, g2) in [("pi_a", false), ("pi_b", true), ("pi_c", false)] {
                        let Some(v) = m.and_then(|m| m.get(key)) else {
                            problems.push(format!("missing the `{key}` field"));
                            continue;
                        };
                        let r = if g2 {
                            formats::snarkjs_g2(v, key)
                                .map(|_| "G2: on curve, in prime-order subgroup")
                        } else {
                            formats::snarkjs_g1(v, key).map(|_| "G1: on curve")
                        };
                        match r {
                            Ok(what) => ok(format!("{key} ({what})"), &mut report),
                            Err(e) => problems.push(e),
                        }
                    }
                }
                Kind::PublicInputs => {
                    let items = json.as_array().map(Vec::as_slice).unwrap_or_default();
                    for (i, s) in items.iter().enumerate() {
                        let what = format!("public[{i}]");
                        match bn254::parse_uint(s, &what)
                            .and_then(|be| bn254::check_scalar(&be, &what))
                        {
                            Ok(()) => ok(format!("{what} (scalar < r)"), &mut report),
                            Err(e) => problems.push(e),
                        }
                    }
                    if items.is_empty() {
                        ok("no public inputs".into(), &mut report);
                    }
                }
            }
        }
        Err(json_err) => match bn254::decode_hex(&text) {
            Some(bytes) if bytes.len() == 256 => {
                report.push_str("type: Groth16 proof bytes (256-byte A || B || C, BN254)\n");
                match formats::Proof::from_bytes(&bytes) {
                    Ok(_) => ok(
                        "A, C (G1: on curve); B (G2: on curve, in prime-order subgroup)".into(),
                        &mut report,
                    ),
                    Err(e) => problems.push(e),
                }
            }
            Some(bytes) => {
                return Err(CliError::failure(format!(
                    "{path}: hex data is {} bytes; only a 256-byte Groth16 proof is recognised",
                    bytes.len()
                )))
            }
            None => {
                return Err(CliError::failure(format!(
                    "{path}: not valid JSON ({json_err}) and not a hex proof"
                )))
            }
        },
    }

    if problems.is_empty() {
        report.push_str("result: OK\n");
        Ok(report)
    } else {
        for p in &problems {
            report.push_str(&format!("  FAIL  {p}\n"));
        }
        report.push_str(&format!("result: FAILED ({} problem(s))", problems.len()));
        Err(CliError::failure(report))
    }
}

fn ok(line: String, report: &mut String) {
    report.push_str(&format!("  ok    {line}\n"));
}

/// Shared entry point for both binaries: runs, prints, and maps errors to
/// exit codes.
pub fn main_with(args: Vec<String>) -> ExitCode {
    match run(&args) {
        Ok(out) => {
            let mut stdout = io::stdout();
            if stdout.write_all(out.as_bytes()).is_err() {
                return ExitCode::from(EXIT_FAILURE);
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(e.code)
        }
    }
}
