use soroban_sdk::Env;

pub fn check_budget() {
    let e = Env::default();
    let _b = e.cost_estimate().budget().get_cpu_insns_consumed();
}
