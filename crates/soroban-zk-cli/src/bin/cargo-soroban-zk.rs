//! `cargo-soroban-zk` binary, so `cargo soroban-zk <command>` works. Cargo
//! runs it as `cargo-soroban-zk soroban-zk <command>`, so the subcommand name
//! is stripped first.

use std::{env, process::ExitCode};

fn main() -> ExitCode {
    let args = soroban_zk_cli::strip_cargo_subcommand(env::args().skip(1).collect());
    soroban_zk_cli::main_with(args)
}
