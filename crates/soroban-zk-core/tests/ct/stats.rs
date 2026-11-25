//! Statistics primitives for the dudect-style timing harness (issue #689).
//!
//! dudect ([Reparaz, Balasch, Verbauwhede, "One Truth Prevails"][paper])
//! classifies timing samples into two input classes and applies **Welch's
//! t-test**. A large absolute t-statistic means the two execution-time
//! distributions are unlikely to have been drawn from the same process, i.e.
//! the operation leaks information about the classified input difference
//! through timing.
//!
//! [paper]: https://eprint.iacr.org/2016/1123
//!
//! This is host-side test infrastructure: it uses `std` and is never compiled
//! into the `no_std` library.

use ethnum::u256;

/// Deterministic xorshift64* PRNG.
///
/// The harness must be reproducible: a failing run can be replayed from the
/// printed seed rather than depending on an external `rand` crate (which would
/// add a dependency to a crate with a tight dependency budget).
pub struct Rng(u64);

impl Rng {
    /// Creates a generator from `seed`. A zero seed is remapped so the state
    /// never collapses to the xorshift fixed point.
    pub const fn new(seed: u64) -> Self {
        Self(if seed == 0 {
            0x9e37_79b9_7f4a_7c15
        } else {
            seed
        })
    }

    /// Returns the next 64 pseudo-random bits.
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    /// Uniform-ish value in `[0, bound)`. `bound` must be non-zero.
    pub fn below(&mut self, bound: u64) -> u64 {
        self.next_u64() % bound
    }

    /// A fair coin, used to interleave the two measurement classes.
    pub fn coin(&mut self) -> bool {
        self.next_u64() & 1 == 1
    }
}

/// Builds a `u256` from a 128-bit high and low half.
fn from_halves(hi: u128, lo: u128) -> u256 {
    (u256::from(hi) << 128) | u256::from(lo)
}

/// Uniform value with at most 252 significant bits.
///
/// Both BN254 moduli (`r`, `q`) are 254 bits, so every 252-bit value is already
/// canonical (no modular reduction is needed before measuring).
pub fn random_u252(rng: &mut Rng) -> u256 {
    let hi = (u128::from(rng.next_u64()) << 64) | u128::from(rng.next_u64());
    let lo = (u128::from(rng.next_u64()) << 64) | u128::from(rng.next_u64());
    from_halves(hi & ((1u128 << 124) - 1), lo)
}

/// Number of set bits (Hamming weight).
pub fn popcount(v: u256) -> u32 {
    let mut count = 0u32;
    for shift in [0usize, 64, 128, 192] {
        count += ((v >> shift).as_u64()).count_ones();
    }
    count
}

/// A uniform 252-bit value with at most two bits set.
///
/// Class "low Hamming weight" for the multiplication and scalar-multiplication
/// scenarios.
pub fn random_low_hamming(rng: &mut Rng) -> u256 {
    let first = rng.below(252) as usize;
    let mut second = rng.below(252) as usize;
    if second == first {
        second = (second + 1) % 252;
    }
    (u256::from(1u8) << first) | (u256::from(1u8) << second)
}

/// A uniform 252-bit value with at least 140 bits set.
///
/// Class "high Hamming weight". Rejection sampling from a 252-bit uniform
/// distribution (mean weight 126) accepts roughly 4% of candidates; the final
/// fallback guarantees termination without changing the value range.
pub fn random_high_hamming(rng: &mut Rng) -> u256 {
    for _ in 0..1024 {
        let candidate = random_u252(rng);
        if popcount(candidate) >= 140 {
            return candidate;
        }
    }
    random_u252(rng) | ((u256::from(1u8) << 140) - u256::from(1u8))
}

/// Mean and unbiased sample variance of `samples`.
///
/// Returns `(0.0, 0.0)` for fewer than two samples. Two passes keep the
/// variance numerically stable; the sample counts here are small enough that
/// the extra pass is free relative to the measured operations.
pub fn mean_var(samples: &[f64]) -> (f64, f64) {
    let n = samples.len();
    if n < 2 {
        return (0.0, 0.0);
    }
    let n_f = n as f64;
    let mean = samples.iter().sum::<f64>() / n_f;
    let sum_sq = samples
        .iter()
        .map(|s| {
            let d = s - mean;
            d * d
        })
        .sum::<f64>();
    (mean, sum_sq / (n_f - 1.0))
}

/// Welch's t-statistic for two independent samples.
///
/// `t = (mean_a - mean_b) / sqrt(var_a / n_a + var_b / n_b)`. The sign is
/// meaningful: negative means class A was faster. If both variances are zero
/// (a degenerate measurement, e.g. a coarse timer) the result is `0.0`.
pub fn welch_t(a: &[f64], b: &[f64]) -> f64 {
    let (mean_a, var_a) = mean_var(a);
    let (mean_b, var_b) = mean_var(b);
    if a.len() < 2 || b.len() < 2 {
        return 0.0;
    }
    let denom = (var_a / a.len() as f64 + var_b / b.len() as f64).sqrt();
    if denom == 0.0 {
        0.0
    } else {
        (mean_a - mean_b) / denom
    }
}

/// Drops the highest `percent`% of samples, in place.
///
/// Wall-clock timing on a shared machine produces occasional large outliers
/// (scheduler preemption, interrupts). dudect discards the slow tail for the
/// same reason: a single 5 ms hiccup in one class dominates the variance and
/// hides or invents a leak. The fast tail is left alone, since the timer's
/// resolution floor is not a glitch.
pub fn trim_high_tail(samples: &mut Vec<f64>, percent: f64) {
    if samples.len() < 20 {
        return;
    }
    let percent = percent.clamp(0.0, 50.0);
    let drop_count =
        ((samples.len() as f64 * percent / 100.0).ceil() as usize).min(samples.len() - 1);
    if drop_count == 0 {
        return;
    }
    samples.sort_by(|x, y| x.partial_cmp(y).unwrap_or(core::cmp::Ordering::Equal));
    samples.truncate(samples.len() - drop_count);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rng_is_deterministic_and_seed_dependent() {
        let mut a = Rng::new(42);
        let mut b = Rng::new(42);
        let mut c = Rng::new(43);
        let seq_a: Vec<u64> = (0..8).map(|_| a.next_u64()).collect();
        let seq_b: Vec<u64> = (0..8).map(|_| b.next_u64()).collect();
        let seq_c: Vec<u64> = (0..8).map(|_| c.next_u64()).collect();
        assert_eq!(seq_a, seq_b);
        assert_ne!(seq_a, seq_c);
        // A zero seed must not collapse the generator.
        assert_ne!(Rng::new(0).next_u64(), 0);
    }

    #[test]
    fn random_u252_stays_below_2_pow_252() {
        let mut rng = Rng::new(7);
        let limit = u256::from(1u8) << 252;
        for _ in 0..256 {
            assert!(random_u252(&mut rng) < limit);
        }
    }

    #[test]
    fn hamming_weight_classes_are_distinct() {
        let mut rng = Rng::new(99);
        let limit = u256::from(1u8) << 252;
        for _ in 0..64 {
            let low = random_low_hamming(&mut rng);
            let high = random_high_hamming(&mut rng);
            assert!(low < limit && high < limit);
            assert_eq!(popcount(low), 2, "low-weight class must have two bits set");
            assert!(popcount(high) >= 140, "high-weight class must be heavy");
        }
    }

    #[test]
    fn popcount_matches_known_vectors() {
        assert_eq!(popcount(u256::from(0u8)), 0);
        assert_eq!(popcount(u256::from(1u8)), 1);
        assert_eq!(popcount(u256::from(0xffu16)), 8);
        assert_eq!(popcount(!u256::from(0u8)), 256);
        // 2^255 has exactly one bit set.
        assert_eq!(popcount(u256::from(1u8) << 255), 1);
    }

    #[test]
    fn welch_t_of_identical_constant_samples_is_zero() {
        let a = vec![10.0f64; 100];
        let b = vec![10.0f64; 100];
        assert_eq!(welch_t(&a, &b), 0.0);
    }

    #[test]
    fn welch_t_has_expected_sign_and_magnitude() {
        // Two tight, well-separated distributions: |t| must be large.
        let a: Vec<f64> = (0..200).map(|i| 100.0 + (i % 5) as f64).collect();
        let b: Vec<f64> = (0..200).map(|i| 200.0 + (i % 5) as f64).collect();
        let t = welch_t(&a, &b);
        assert!(t < -50.0, "expected strongly negative t, got {t}");
        assert!(welch_t(&b, &a) > 50.0, "sign must flip with class order");
        // Identical distributions of noisy data: no significant difference.
        let c: Vec<f64> = (0..200).map(|i| (i % 37) as f64).collect();
        let d: Vec<f64> = (0..200).map(|i| (i % 41) as f64).collect();
        assert!(welch_t(&c, &d).abs() < 10.0);
    }

    #[test]
    fn welch_t_handles_degenerate_inputs() {
        assert_eq!(welch_t(&[], &[]), 0.0);
        assert_eq!(welch_t(&[1.0], &[2.0]), 0.0);
    }

    #[test]
    fn trim_removes_only_the_slow_tail() {
        let mut samples: Vec<f64> = (0..1000).map(f64::from).collect();
        samples[999] = 1_000_000.0;
        trim_high_tail(&mut samples, 1.0);
        assert_eq!(samples.len(), 990);
        assert!(!samples.contains(&1_000_000.0));
        assert_eq!(samples[0], 0.0, "fast tail must be preserved");
    }

    #[test]
    fn trim_is_a_noop_for_tiny_samples() {
        let mut samples = vec![1.0, 2.0, 3.0];
        trim_high_tail(&mut samples, 1.0);
        assert_eq!(samples.len(), 3);
    }
}
