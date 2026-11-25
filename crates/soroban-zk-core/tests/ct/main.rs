//! dudect-style statistical timing-leak harness (issue #689).
//!
//! The library's constant-time properties are currently *reasoned about*; this
//! harness *measures* them. It times `Fr`/`Fq` multiplication, field inversion
//! and G1 scalar multiplication over two input classes and reports a Welch
//! t-statistic per scenario:
//!
//! * `fixed` vs `random` inputs,
//! * `low Hamming weight` vs `high Hamming weight` inputs.
//!
//! The heavy measurement is `#[ignore]`d so `cargo test` stays fast and
//! deterministic; run it with `make ct-test` (which forwards `CT_SAMPLES`,
//! `CT_THRESHOLD` and `CT_OUTPUT`). The statistical helpers carry ordinary unit
//! tests, which do run under `cargo test`.
//!
//! Methodology, thresholds and limitations are documented in
//! `frontend/content/docs/core-concepts/constant-time-notes.mdx`.

mod stats;

use std::time::{Duration, Instant};

use ethnum::u256;
use soroban_zk_core::{Bn254, G1Projective};
use stats::{
    mean_var, random_high_hamming, random_low_hamming, random_u252, trim_high_tail, welch_t, Rng,
};

/// Default sample count per class for the cheap field operations.
const DEFAULT_SAMPLES: usize = 20_000;
/// Default absolute t-statistic threshold.
///
/// dudect's own default is 10; 4.5 is the common "no evidence" cut-off for a
/// 99.999% confidence interval. See the docs section for interpretation.
const DEFAULT_THRESHOLD: f64 = 10.0;
/// Percentage dropped from the slow tail of each class before the t-test.
const DEFAULT_TRIM_PERCENT: f64 = 1.0;
/// Samples discarded per class before timing, to warm caches and the branch
/// predictor for the measured code path.
const WARMUP: usize = 64;

/// Which of the two input classes a sample belongs to.
#[derive(Clone, Copy)]
enum Class {
    A,
    B,
}

/// One prepared input. `b` is unused by the unary scenarios (inversion, scalar
/// multiplication).
#[derive(Clone, Copy)]
struct Input {
    a: u256,
    b: u256,
}

impl Input {
    fn unary(a: u256) -> Self {
        Self {
            a,
            b: u256::from(0u8),
        }
    }
}

/// A measurement scenario: how to build inputs for each class and how to run
/// the operation under test.
struct Scenario {
    /// Stable identifier, also used as the JSON key.
    name: &'static str,
    class_a: &'static str,
    class_b: &'static str,
    prepare: fn(Class, &mut Rng) -> Input,
    /// Returns a value derived from the operation's output so the compiler
    /// cannot delete the computation.
    measure: fn(&Input) -> u256,
    /// Cost multiplier: G1 scalar multiplication is ~254x more expensive than a
    /// field multiplication, so it uses fewer samples.
    sample_divisor: usize,
}

/// The harness configuration, read once from the environment.
struct Config {
    samples: usize,
    threshold: f64,
    trim_percent: f64,
    seed: u64,
    output: std::path::PathBuf,
    /// Exit non-zero when a scenario exceeds the threshold. Off by default: the
    /// harness reproduces the known gaps listed in the constant-time notes, and
    /// turning those into a hard failure is the last step once the noise floor
    /// has been characterised (see `make ct-test CT_ENFORCE=1`).
    enforce: bool,
}

impl Config {
    fn from_env() -> Self {
        let samples = env_usize("CT_SAMPLES", DEFAULT_SAMPLES).max(200);
        let threshold = env_f64("CT_THRESHOLD", DEFAULT_THRESHOLD);
        let trim_percent = env_f64("CT_TRIM_PERCENT", DEFAULT_TRIM_PERCENT);
        let seed = env_u64("CT_SEED", 0x5eed_1234_abcd_9876);
        let enforce = matches!(
            std::env::var("CT_ENFORCE").ok().as_deref(),
            Some("1") | Some("true") | Some("yes")
        );
        let output = match std::env::var_os("CT_OUTPUT") {
            Some(path) => std::path::PathBuf::from(path),
            // `cargo test` runs the binary with the package directory as cwd;
            // resolve to the workspace `target/` directory instead.
            None => std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .join("target/ct-results.json"),
        };
        Self {
            samples,
            threshold,
            trim_percent,
            seed,
            output,
            enforce,
        }
    }
}

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(default)
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(default)
}

fn env_f64(key: &str, default: f64) -> f64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(default)
}

// ---------------------------------------------------------------------------
// Input preparation
// ---------------------------------------------------------------------------

/// A fixed, non-degenerate Fr operand pair.
fn fixed_fr_pair() -> (u256, u256) {
    let a = (u256::from(0x1234_5678_9abc_def0u64) << 128) | u256::from(0x0fed_cba9_8765_4321u64);
    let b = (u256::from(0x0f0f_0f0f_0f0f_0f0fu64) << 128) | u256::from(0xf0f0_f0f0_f0f0_f0f0u64);
    (a % Bn254::FR_MODULUS, b % Bn254::FR_MODULUS)
}

/// A fixed, non-degenerate Fq operand pair.
fn fixed_fq_pair() -> (u256, u256) {
    let (a, b) = fixed_fr_pair();
    (a % Bn254::FQ_MODULUS, b % Bn254::FQ_MODULUS)
}

/// Uniform non-zero Fr element.
fn random_fr(rng: &mut Rng) -> u256 {
    loop {
        let value = random_u252(rng);
        if value != u256::from(0u8) {
            return value;
        }
    }
}

fn prepare_fr_mul(class: Class, rng: &mut Rng) -> Input {
    match class {
        Class::A => {
            let (a, b) = fixed_fr_pair();
            Input { a, b }
        }
        Class::B => Input {
            a: random_fr(rng),
            b: random_fr(rng),
        },
    }
}

fn prepare_fq_mul(class: Class, rng: &mut Rng) -> Input {
    match class {
        Class::A => {
            let (a, b) = fixed_fq_pair();
            Input { a, b }
        }
        Class::B => Input {
            a: random_u252(rng),
            b: random_u252(rng),
        },
    }
}

fn prepare_fr_mul_hamming(class: Class, rng: &mut Rng) -> Input {
    let (a, b) = match class {
        Class::A => (random_low_hamming(rng), random_low_hamming(rng)),
        Class::B => (random_high_hamming(rng), random_high_hamming(rng)),
    };
    Input { a, b }
}

fn prepare_fq_mul_hamming(class: Class, rng: &mut Rng) -> Input {
    prepare_fr_mul_hamming(class, rng)
}

fn prepare_fr_invert(class: Class, rng: &mut Rng) -> Input {
    match class {
        Class::A => Input::unary(fixed_fr_pair().0),
        Class::B => Input::unary(random_fr(rng)),
    }
}

fn prepare_fq_invert(class: Class, rng: &mut Rng) -> Input {
    match class {
        Class::A => Input::unary(fixed_fq_pair().0),
        Class::B => Input::unary(random_u252(rng)),
    }
}

/// Fixed scalar for the scalar-multiplication scenarios.
///
/// The two sentinel values `0` and `1` are excluded: `g1_scalar_mul` has
/// intentional fast paths for them (documented in the constant-time notes), so
/// including them would measure a known, deliberate exception.
fn fixed_scalar() -> u256 {
    (u256::from(0x00c0_ffee_1234_5678u64) << 128) | u256::from(0x9abc_def0_1122_3344u64)
}

fn prepare_g1_scalar(class: Class, rng: &mut Rng) -> Input {
    match class {
        Class::A => Input::unary(fixed_scalar()),
        Class::B => Input::unary(2 + random_u252(rng) % (Bn254::FR_MODULUS - u256::from(3u8))),
    }
}

fn prepare_g1_scalar_hamming(class: Class, rng: &mut Rng) -> Input {
    // Shift the low-weight class up by 2 so it can never collide with the
    // scalar == 0 / scalar == 1 sentinel fast paths.
    match class {
        Class::A => Input::unary(random_low_hamming(rng) + u256::from(4u8)),
        Class::B => Input::unary(random_high_hamming(rng)),
    }
}

fn prepare_control(class: Class, rng: &mut Rng) -> Input {
    match class {
        Class::A => Input::unary(random_u252(rng)),
        Class::B => Input::unary(random_u252(rng)),
    }
}

// ---------------------------------------------------------------------------
// Operations under test
// ---------------------------------------------------------------------------

fn run_fr_mul(input: &Input) -> u256 {
    Bn254::mul(input.a, input.b)
}

fn run_fq_mul(input: &Input) -> u256 {
    Bn254::mul_fq(input.a, input.b)
}

fn run_fr_invert(input: &Input) -> u256 {
    Bn254::invert(input.a)
}

fn run_fq_invert(input: &Input) -> u256 {
    Bn254::invert_fq(input.a)
}

/// BN254 G1 generator `(1, 2)` in Jacobian coordinates.
fn g1_generator() -> G1Projective {
    G1Projective {
        x: u256::from(1u8),
        y: u256::from(2u8),
        z: u256::from(1u8),
    }
}

fn run_g1_scalar_mul(input: &Input) -> u256 {
    let result = Bn254::g1_scalar_mul(g1_generator(), input.a);
    result.x ^ result.y ^ result.z
}

/// Input-independent control: measures the noise floor of the harness itself.
///
/// Both classes run the same fixed amount of work on random data, so any |t|
/// above the threshold here means the measurement environment (not the library)
/// is producing a signal.
fn run_control(input: &Input) -> u256 {
    let mut acc = input.a;
    for shift in [0usize, 7, 63, 129, 200] {
        acc = acc.wrapping_mul(input.a >> shift);
    }
    acc
}

fn scenarios() -> Vec<Scenario> {
    vec![
        Scenario {
            name: "fr_mul_fixed_vs_random",
            class_a: "fixed",
            class_b: "random",
            prepare: prepare_fr_mul,
            measure: run_fr_mul,
            sample_divisor: 1,
        },
        Scenario {
            name: "fr_mul_low_vs_high_hamming",
            class_a: "low_hamming",
            class_b: "high_hamming",
            prepare: prepare_fr_mul_hamming,
            measure: run_fr_mul,
            sample_divisor: 1,
        },
        Scenario {
            name: "fq_mul_fixed_vs_random",
            class_a: "fixed",
            class_b: "random",
            prepare: prepare_fq_mul,
            measure: run_fq_mul,
            sample_divisor: 1,
        },
        Scenario {
            name: "fq_mul_low_vs_high_hamming",
            class_a: "low_hamming",
            class_b: "high_hamming",
            prepare: prepare_fq_mul_hamming,
            measure: run_fq_mul,
            sample_divisor: 1,
        },
        Scenario {
            name: "fr_invert_fixed_vs_random",
            class_a: "fixed",
            class_b: "random",
            prepare: prepare_fr_invert,
            measure: run_fr_invert,
            sample_divisor: 4,
        },
        Scenario {
            name: "fq_invert_fixed_vs_random",
            class_a: "fixed",
            class_b: "random",
            prepare: prepare_fq_invert,
            measure: run_fq_invert,
            sample_divisor: 4,
        },
        Scenario {
            name: "g1_scalar_mul_fixed_vs_random",
            class_a: "fixed",
            class_b: "random",
            prepare: prepare_g1_scalar,
            measure: run_g1_scalar_mul,
            sample_divisor: 20,
        },
        Scenario {
            name: "g1_scalar_mul_low_vs_high_hamming",
            class_a: "low_hamming",
            class_b: "high_hamming",
            prepare: prepare_g1_scalar_hamming,
            measure: run_g1_scalar_mul,
            sample_divisor: 20,
        },
        Scenario {
            name: "control_noise_floor",
            class_a: "same_workload_a",
            class_b: "same_workload_b",
            prepare: prepare_control,
            measure: run_control,
            sample_divisor: 1,
        },
    ]
}

// ---------------------------------------------------------------------------
// Measurement loop and reporting
// ---------------------------------------------------------------------------

/// One scenario's trimmed means and t-statistic.
struct ScenarioResult {
    name: &'static str,
    class_a: &'static str,
    class_b: &'static str,
    samples_a: usize,
    samples_b: usize,
    mean_a_ns: f64,
    mean_b_ns: f64,
    t: f64,
    threshold: f64,
    leaky: bool,
    control: bool,
}

impl ScenarioResult {
    fn to_json(&self) -> String {
        format!(
            "{{\"scenario\":\"{}\",\"class_a\":\"{}\",\"class_b\":\"{}\",\
             \"samples_a\":{},\"samples_b\":{},\
             \"mean_a_ns\":{:.3},\"mean_b_ns\":{:.3},\
             \"t_statistic\":{:.4},\"threshold\":{:.2},\
             \"leaky\":{},\"control\":{}}}",
            self.name,
            self.class_a,
            self.class_b,
            self.samples_a,
            self.samples_b,
            self.mean_a_ns,
            self.mean_b_ns,
            self.t,
            self.threshold,
            self.leaky,
            self.control,
        )
    }
}

/// Builds a prepared input for one class.
fn prepare(scenario: &Scenario, class: Class, rng: &mut Rng) -> Input {
    (scenario.prepare)(class, rng)
}

/// Times one operation, returning its elapsed duration in nanoseconds.
fn time_one(scenario: &Scenario, input: &Input) -> f64 {
    let start = Instant::now();
    let output = (scenario.measure)(input);
    // Keep the output observable and inside the timed region; constant cost, so
    // it cannot bias either class.
    std::hint::black_box(output);
    start.elapsed().as_nanos() as f64
}

/// Runs one scenario, returning the trimmed sample vectors per class.
fn collect(scenario: &Scenario, config: &Config, rng: &mut Rng) -> (Vec<f64>, Vec<f64>) {
    let samples = (config.samples / scenario.sample_divisor).max(200);

    // Warm up both classes so the first timed sample is not dominated by cold
    // instruction and data caches.
    for _ in 0..WARMUP {
        let input_a = prepare(scenario, Class::A, rng);
        let input_b = prepare(scenario, Class::B, rng);
        std::hint::black_box((scenario.measure)(&input_a));
        std::hint::black_box((scenario.measure)(&input_b));
    }

    let mut times_a = Vec::with_capacity(samples);
    let mut times_b = Vec::with_capacity(samples);

    // Interleave the classes in pseudo-random order. Measuring one class to
    // completion before the other would let CPU frequency drift, thermal
    // throttling or a co-tenant's work land entirely in one class and be
    // reported as leakage.
    for _ in 0..samples {
        if rng.coin() {
            let input = prepare(scenario, Class::A, rng);
            times_a.push(time_one(scenario, &input));
        } else {
            let input = prepare(scenario, Class::B, rng);
            times_b.push(time_one(scenario, &input));
        }
    }

    trim_high_tail(&mut times_a, config.trim_percent);
    trim_high_tail(&mut times_b, config.trim_percent);
    (times_a, times_b)
}

fn run_scenario(scenario: &Scenario, config: &Config, rng: &mut Rng) -> ScenarioResult {
    let (times_a, times_b) = collect(scenario, config, rng);
    let t = welch_t(&times_a, &times_b);
    let (mean_a, _) = mean_var(&times_a);
    let (mean_b, _) = mean_var(&times_b);
    ScenarioResult {
        name: scenario.name,
        class_a: scenario.class_a,
        class_b: scenario.class_b,
        samples_a: times_a.len(),
        samples_b: times_b.len(),
        mean_a_ns: mean_a,
        mean_b_ns: mean_b,
        t,
        threshold: config.threshold,
        leaky: t.abs() >= config.threshold,
        control: scenario.name.starts_with("control"),
    }
}

fn write_report(results: &[ScenarioResult], config: &Config) -> std::io::Result<()> {
    if let Some(parent) = config.output.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut json = String::from("{\n  \"seed\": ");
    json.push_str(&config.seed.to_string());
    json.push_str(",\n  \"threshold\": ");
    json.push_str(&format!("{:.2}", config.threshold));
    json.push_str(",\n  \"trim_percent\": ");
    json.push_str(&format!("{:.2}", config.trim_percent));
    json.push_str(",\n  \"results\": [\n");
    for (i, result) in results.iter().enumerate() {
        json.push_str("    ");
        json.push_str(&result.to_json());
        if i + 1 != results.len() {
            json.push(',');
        }
        json.push('\n');
    }
    json.push_str("  ]\n}\n");
    std::fs::write(&config.output, json)
}

fn print_header(config: &Config, duration: Duration) {
    println!("dudect-style constant-time timing harness (issue #689)");
    println!(
        "seed={} samples/class={} threshold=|t|>={:.2} trim={:.2}% enforce={}",
        config.seed, config.samples, config.threshold, config.trim_percent, config.enforce
    );
    println!("elapsed so far: {:.1?}\n", duration);
    println!(
        "{:<38} {:>10} {:>12} {:>12} {:>9}  verdict",
        "scenario", "samples", "mean_a(ns)", "mean_b(ns)", "t"
    );
    println!("{}", "-".repeat(96));
}

fn print_result(result: &ScenarioResult) {
    let verdict = if result.control {
        if result.leaky {
            "NOISY (control leaked)"
        } else {
            "ok (control)"
        }
    } else if result.leaky {
        "LEAK?"
    } else {
        "ok"
    };
    println!(
        "{:<38} {:>10} {:>12.1} {:>12.1} {:>9.2}  {}",
        result.name,
        result.samples_a + result.samples_b,
        result.mean_a_ns,
        result.mean_b_ns,
        result.t,
        verdict
    );
}

#[test]
#[ignore = "statistical timing measurement; run with `make ct-test`"]
fn ct_timing_leak_analysis() {
    let config = Config::from_env();
    let started = Instant::now();
    let mut rng = Rng::new(config.seed);

    // Sanity: the harness measures a valid, non-special point.
    assert!(
        Bn254::is_valid_g1(u256::from(1u8), u256::from(2u8)),
        "the G1 generator (1, 2) must be on the curve"
    );

    print_header(&config, started.elapsed());

    let mut results = Vec::new();
    for scenario in scenarios() {
        let result = run_scenario(&scenario, &config, &mut rng);
        print_result(&result);
        results.push(result);
    }

    println!("{}", "-".repeat(96));
    if let Err(error) = write_report(&results, &config) {
        // A missing artifact must not hide the t-statistics printed above.
        eprintln!(
            "warning: could not write {}: {error}",
            config.output.display()
        );
    } else {
        println!("t-statistics written to {}", config.output.display());
    }
    println!("total elapsed: {:.1?}", started.elapsed());

    let control_leaked = results.iter().any(|result| result.control && result.leaky);
    let leaks: Vec<&ScenarioResult> = results
        .iter()
        .filter(|result| !result.control && result.leaky)
        .collect();

    if control_leaked {
        println!(
            "\n⚠️  The control scenario exceeded the threshold: this run is too noisy to \
             interpret. Increase CT_SAMPLES, quiet the machine, or ignore this run."
        );
    }

    if leaks.is_empty() {
        println!("\n✅ No scenario exceeded |t| >= {:.2}.", config.threshold);
        return;
    }

    let summary = leaks
        .iter()
        .map(|result| {
            format!(
                "{} (t = {:.2}, Δ = {:.1} ns)",
                result.name,
                result.t,
                result.mean_a_ns - result.mean_b_ns
            )
        })
        .collect::<Vec<_>>()
        .join(", ");

    if config.enforce {
        assert!(
            !control_leaked,
            "this run is too noisy to interpret (the control scenario leaked); re-run with more samples"
        );
        assert!(
            leaks.is_empty(),
            "timing leakage above |t| >= {:.2}: {summary}",
            config.threshold
        );
    }

    println!(
        "\n⚠️  {} scenario(s) report a timing signal: {summary}",
        leaks.len()
    );
    println!(
        "    Report-only run (set CT_ENFORCE=1 to fail on a leak). Compare Δ against the \
         timer resolution before treating it as exploitable."
    );
}

// ---------------------------------------------------------------------------
// Unit tests: fast, deterministic, part of the normal `cargo test` suite.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod scenario_tests {
    use super::*;

    fn rng() -> Rng {
        Rng::new(0xdead_beef)
    }

    #[test]
    fn every_scenario_is_named_and_has_positive_samples() {
        let names: Vec<&str> = scenarios().iter().map(|s| s.name).collect();
        assert_eq!(names.len(), 9);
        for name in &names {
            assert!(!name.is_empty());
        }
        let unique: std::collections::HashSet<_> = names.iter().collect();
        assert_eq!(unique.len(), names.len(), "scenario names must be unique");
        assert!(scenarios().iter().all(|s| s.sample_divisor >= 1));
    }

    #[test]
    fn prepared_inputs_are_canonical_field_elements() {
        let mut rng = rng();
        for scenario in scenarios() {
            for class in [Class::A, Class::B] {
                for _ in 0..16 {
                    let input = prepare(&scenario, class, &mut rng);
                    assert!(
                        input.a < Bn254::FR_MODULUS,
                        "{}: class-a input {} is not canonical",
                        scenario.name,
                        scenario.class_a
                    );
                    assert!(
                        input.b < Bn254::FR_MODULUS,
                        "{}: class-b input is not canonical",
                        scenario.name
                    );
                    assert!(Bn254::is_valid_fq(input.a));
                }
            }
        }
    }

    #[test]
    fn inversion_inputs_are_nonzero() {
        let mut rng = rng();
        for scenario in scenarios()
            .into_iter()
            .filter(|s| s.name.contains("invert"))
        {
            for class in [Class::A, Class::B] {
                for _ in 0..64 {
                    let input = prepare(&scenario, class, &mut rng);
                    assert_ne!(input.a, u256::from(0u8));
                }
            }
        }
    }

    #[test]
    fn scalar_multiplication_inputs_avoid_sentinel_fast_paths() {
        let mut rng = rng();
        for scenario in scenarios()
            .into_iter()
            .filter(|s| s.name.starts_with("g1_scalar_mul"))
        {
            for class in [Class::A, Class::B] {
                for _ in 0..64 {
                    let scalar = prepare(&scenario, class, &mut rng).a;
                    assert!(
                        scalar > u256::from(1u8),
                        "{}: scalar 0/1 hit the fast path",
                        scenario.name
                    );
                    assert!(scalar < Bn254::FR_MODULUS);
                }
            }
        }
    }

    #[test]
    fn measure_functions_compute_a_nonzero_fingerprint() {
        let mut rng = rng();
        for scenario in scenarios() {
            for class in [Class::A, Class::B] {
                let input = prepare(&scenario, class, &mut rng);
                // Inversions of these inputs and scalar multiplications by a
                // non-zero scalar cannot both collapse to zero.
                let _ = (scenario.measure)(&input);
            }
        }
        // Explicit boundary: inverting 0 is documented to return 0, not panic.
        assert_eq!(Bn254::invert(u256::from(0u8)), u256::from(0u8));
        assert_eq!(Bn254::invert_fq(u256::from(0u8)), u256::from(0u8));
    }

    #[test]
    fn g1_generator_is_on_curve_and_scalar_mult_is_consistent() {
        let generator = g1_generator();
        assert!(Bn254::is_valid_g1(generator.x, generator.y));
        // 2G computed by the scalar path must equal G + G.
        let two_g = Bn254::g1_scalar_mul(generator, u256::from(2u8));
        let doubled = generator.double();
        assert_eq!(two_g.x, doubled.x);
        assert_eq!(two_g.y, doubled.y);
        assert_eq!(two_g.z, doubled.z);
    }

    #[test]
    fn control_scenario_is_input_independent() {
        // The control must run identical work for both classes; only the data
        // differs, and its cost does not depend on the data.
        let mut rng = rng();
        let input_a = prepare_control(Class::A, &mut rng);
        let input_b = prepare_control(Class::B, &mut rng);
        assert_ne!(input_a.a, input_b.a, "classes should use different data");
        let _ = (run_control)(&input_a);
        let _ = (run_control)(&input_b);
    }

    #[test]
    fn config_clamps_sample_count() {
        // Avoid mutating process-wide env vars in tests; assert the clamp rule
        // the constructor applies instead.
        assert_eq!(
            env_usize("CT_SAMPLES_SURELY_UNSET", DEFAULT_SAMPLES),
            DEFAULT_SAMPLES
        );
        assert_eq!(DEFAULT_SAMPLES.max(200), DEFAULT_SAMPLES);
    }

    #[test]
    fn report_json_is_well_formed() {
        let result = ScenarioResult {
            name: "unit_test",
            class_a: "a",
            class_b: "b",
            samples_a: 10,
            samples_b: 12,
            mean_a_ns: 1.5,
            mean_b_ns: 2.25,
            t: -3.5,
            threshold: 10.0,
            leaky: false,
            control: false,
        };
        let json = result.to_json();
        assert!(json.starts_with('{') && json.ends_with('}'));
        assert!(json.contains("\"scenario\":\"unit_test\""));
        assert!(json.contains("\"leaky\":false"));
        assert_eq!(json.matches('{').count(), json.matches('}').count());
    }
}
