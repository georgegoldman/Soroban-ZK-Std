#![cfg(test)]
use soroban_sdk::Env;

#[test]
fn test_budget() {
    let env = Env::default();
    let b = env.cost_estimate().budget();
    let _ = b.cpu_instruction_cost();
}
