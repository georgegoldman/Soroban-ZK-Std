//! `soroban-zk` binary.

use std::{env, process::ExitCode};

fn main() -> ExitCode {
    soroban_zk_cli::main_with(env::args().skip(1).collect())
}
