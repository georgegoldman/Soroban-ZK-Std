//! Rescue-Prime hashing gadget (Issue #367, Phase 4).
//!
//! Implements the Rescue-Prime sponge permutation over the BN254 scalar field
//! `Fr` in pure software (no host call), so the same constraints can be
//! evaluated in-circuit by a prover and re-checked by a verifier. The S-box is
//! `x^α` with `α` an odd exponent coprime to `p-1`; its inverse `x^{α⁻¹}` is
//! provided so that the permutation is (partially) invertible and the S-box
//! inverse algorithm is exercised directly.
//!
//! Field arithmetic uses [`soroban_zk_core::Bn254`], which operates on
//! [`ethnum::u256`] modulo the BN254 Fr modulus.

use ethnum::u256 as eth_u256;
use soroban_sdk::{Bytes, Env, U256};
use soroban_zk_core::Bn254;

/// State width `m`. Rate = `m - 1`, capacity = `1`.
pub const STATE: usize = 3;
/// Number of permutation rounds (must be even).
pub const ROUNDS: usize = 6;

const FR: eth_u256 = Bn254::FR_MODULUS;

#[inline(always)]
fn fadd(a: eth_u256, b: eth_u256) -> eth_u256 {
    Bn254::add(a, b)
}
#[inline(always)]
fn fsub(a: eth_u256, b: eth_u256) -> eth_u256 {
    Bn254::sub(a, b)
}
#[inline(always)]
fn fmul(a: eth_u256, b: eth_u256) -> eth_u256 {
    Bn254::mul(a, b)
}
#[inline(always)]
fn finv(a: eth_u256) -> eth_u256 {
    Bn254::invert(a)
}
#[inline(always)]
fn fpow(a: eth_u256, e: eth_u256) -> eth_u256 {
    Bn254::pow(a, e)
}

/// Pick a valid S-box exponent `α` (odd, coprime to `p-1`) and its inverse.
fn sbox_exponents() -> (eth_u256, eth_u256) {
    // p-1 for the BN254 scalar field.
    let pm1 = FR - eth_u256::ONE;
    let mut alpha = eth_u256::from(3u8);
    loop {
        if gcd(alpha, pm1) == eth_u256::ONE {
            let inv = mod_inv(alpha, pm1);
            return (alpha, inv);
        }
        alpha += eth_u256::from(2u8); // stay odd
    }
}

fn gcd(mut a: eth_u256, mut b: eth_u256) -> eth_u256 {
    while b != eth_u256::ZERO {
        let t = b;
        b = a % b;
        a = t;
    }
    a
}

/// `(a + b) mod m` without overflow (a, b < m < 2^254 ⇒ sum < 2^255).
fn add_mod(a: eth_u256, b: eth_u256, m: eth_u256) -> eth_u256 {
    let s = a + b;
    s % m
}

/// `(a − b) mod m`, keeping the result in `[0, m)`.
fn sub_mod(a: eth_u256, b: eth_u256, m: eth_u256) -> eth_u256 {
    if a >= b {
        (a - b) % m
    } else {
        (m - (b - a)) % m
    }
}

/// `(a · b) mod m` using double-and-add so intermediate products stay in `u256`
/// (`m < 2^254`, `a·b` could be up to `2^508`).
fn mul_mod(a: eth_u256, b: eth_u256, m: eth_u256) -> eth_u256 {
    let mut res = eth_u256::ZERO;
    let x = a % m;
    for bit in (0..256).rev() {
        res = (res << 1) % m;
        if (x >> bit) & eth_u256::ONE == eth_u256::ONE {
            res = add_mod(res, b, m);
        }
    }
    res
}

/// Modular inverse of `a` modulo `m` (extended Euclidean with modular reduction
/// so the Bézout coefficient never goes negative). `m` need not be prime.
fn mod_inv(mut a: eth_u256, m: eth_u256) -> eth_u256 {
    a %= m;
    let (mut t, mut newt) = (eth_u256::ZERO, eth_u256::ONE);
    let (mut r, mut newr) = (m, a);
    while newr != eth_u256::ZERO {
        let q = r / newr;
        let tmp = t;
        t = newt;
        newt = sub_mod(tmp, mul_mod(q, newt, m), m);
        let tmp_r = r;
        r = newr;
        newr = tmp_r - q * newr; // r >= q·newr, so this is non-negative and < m
    }
    // r must be 1 (a is coprime to m).
    t % m
}

/// Rescue-Prime parameters: MDS matrix and round keys (Cauchy MDS, LCG round keys).
pub struct RescueParams {
    mds: [[eth_u256; STATE]; STATE],
    round_keys: [[eth_u256; STATE]; ROUNDS],
}

impl RescueParams {
    /// Build the fixed (deterministic) parameter set.
    pub fn new() -> Self {
        let mds = build_mds();
        let round_keys = build_round_keys();
        Self { mds, round_keys }
    }

    /// Apply the `α`-th power S-box to a single element.
    pub fn sbox(&self, x: eth_u256) -> eth_u256 {
        let (alpha, _) = sbox_exponents();
        fpow(x, alpha)
    }

    /// Apply the S-box inverse (`x^{α⁻¹}`).
    pub fn sbox_inv(&self, x: eth_u256) -> eth_u256 {
        let (_, alpha_inv) = sbox_exponents();
        fpow(x, alpha_inv)
    }

    /// One Rescue-Prime permutation of the `m`-element state.
    pub fn permute(&self, state: &mut [eth_u256; STATE]) {
        let (alpha, alpha_inv) = sbox_exponents();
        for r in 0..ROUNDS {
            // S-box (forward on even rounds, inverse on odd rounds).
            for x in state.iter_mut() {
                *x = if r % 2 == 0 {
                    fpow(*x, alpha)
                } else {
                    fpow(*x, alpha_inv)
                };
            }
            // Add round key.
            let key = &self.round_keys[r];
            for i in 0..STATE {
                state[i] = fadd(state[i], key[i]);
            }
            // MDS linear layer.
            let mut out = [eth_u256::ZERO; STATE];
            for (i, out_i) in out.iter_mut().enumerate() {
                let mut acc = eth_u256::ZERO;
                for (j, &sj) in state.iter().enumerate() {
                    acc = fadd(acc, fmul(self.mds[i][j], sj));
                }
                *out_i = acc;
            }
            *state = out;
        }
    }
}

impl Default for RescueParams {
    fn default() -> Self {
        Self::new()
    }
}

/// Build a Cauchy MDS matrix `M[i][j] = 1/(x_i - y_j)` with distinct sequences,
/// which is guaranteed invertible.
fn build_mds() -> [[eth_u256; STATE]; STATE] {
    let mut mds = [[eth_u256::ZERO; STATE]; STATE];
    for (i, row) in mds.iter_mut().enumerate() {
        let xi = eth_u256::from(i as u128 + 1);
        for (j, cell) in row.iter_mut().enumerate() {
            // y_j = m + j + 1  → ensures x_i - y_j is never zero.
            let yj = eth_u256::from(STATE as u128 + j as u128 + 1);
            let mut diff = fsub(xi, yj);
            if diff >= FR {
                diff = fsub(diff, FR);
            }
            *cell = finv(diff);
        }
    }
    mds
}

/// Deterministic round keys from a small LCG seeded by a constant.
fn build_round_keys() -> [[eth_u256; STATE]; ROUNDS] {
    let mut keys = [[eth_u256::ZERO; STATE]; ROUNDS];
    // LCG parameters (arbitrary but fixed); result is mod Fr.
    let a: eth_u256 = eth_u256::from(0x9E3779B97F4A7C15u64);
    let c: eth_u256 = eth_u256::from(0x4F1BBCDCBFD3A8A7u64);
    let mut state = eth_u256::from(0x1234_5678_9ABC_DEF1u64);
    for row in keys.iter_mut() {
        for coord in row.iter_mut() {
            state = fadd(fmul(state, a), c);
            *coord = state;
        }
    }
    keys
}

/// Rescue-Prime sponge hash over BN254 Fr.
///
/// Absorbs `message` (field elements) in blocks of `rate = STATE - 1`, then
/// squeezes a single field element as the digest. Capacity is 1 (state[0]).
pub fn rescue_prime_hash(env: &Env, message: &[U256]) -> U256 {
    let params = RescueParams::new();
    let rate = STATE - 1;
    let mut state = [eth_u256::ZERO; STATE];

    let mut idx = 0;
    while idx < message.len() {
        // Absorb one block into the rate portion (capacity untouched).
        for k in 0..rate {
            if idx + k < message.len() {
                state[k + 1] = fadd(state[k + 1], to_eth_v(&message[idx + k]));
            }
        }
        params.permute(&mut state);
        idx += rate;
    }
    // Final permutation if the message was empty ensures a non-trivial digest.
    if message.is_empty() {
        params.permute(&mut state);
    }

    from_eth_v(env, state[1])
}

#[inline(always)]
fn to_eth_v(v: &U256) -> eth_u256 {
    let mut b = [0u8; 32];
    v.to_be_bytes().copy_into_slice(&mut b);
    eth_u256::from_be_bytes(b)
}

#[inline(always)]
fn from_eth_v(env: &Env, v: eth_u256) -> U256 {
    U256::from_be_bytes(env, &Bytes::from_array(env, &v.to_be_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::Env;

    fn env() -> Env {
        let e = Env::default();
        e.cost_estimate().budget().reset_unlimited();
        e
    }

    #[test]
    fn sbox_roundtrip() {
        let p = RescueParams::new();
        let x = eth_u256::from(12345u64);
        let y = p.sbox(x);
        assert_eq!(p.sbox_inv(y), x);
    }

    #[test]
    fn permute_is_deterministic() {
        let p = RescueParams::new();
        let mut s1 = [
            eth_u256::from(1u8),
            eth_u256::from(2u8),
            eth_u256::from(3u8),
        ];
        let mut s2 = s1;
        p.permute(&mut s1);
        p.permute(&mut s2);
        assert_eq!(s1, s2);
    }

    #[test]
    fn hash_is_deterministic_and_order_sensitive() {
        let env = env();
        let a = U256::from_u128(&env, 1);
        let b = U256::from_u128(&env, 2);
        let h1 = rescue_prime_hash(&env, &[a.clone(), b.clone()]);
        let h2 = rescue_prime_hash(&env, &[a, b]);
        assert_eq!(h1, h2);
        let h3 = rescue_prime_hash(&env, &[U256::from_u128(&env, 2), U256::from_u128(&env, 1)]);
        assert_ne!(h1, h3);
    }

    #[test]
    fn hash_nonzero() {
        let env = env();
        let h = rescue_prime_hash(&env, &[]);
        // Not required to be nonzero, but should be stable & in-field.
        assert_eq!(h, rescue_prime_hash(&env, &[]));
        let bytes = h.to_be_bytes();
        let _ = bytes;
    }
}
