//! Circomlib-compatible MiMC-7 and MiMC Feistel sponge over BN254 Fr
//! (Issue #609).
//!
//! Round constants are derived at call time from Keccak-256 exactly as
//! `circomlibjs` does, so no constant tables are embedded in the WASM:
//! `c = keccak(seed); c = keccak(c); cts[i] = c mod r`.

use ethnum::u256;
use soroban_sdk::{Bytes, Env, Vec, U256};
use soroban_zk_core::{Bn254, ZkError};

const MIMC7_SEED: &[u8] = b"mimc";
const MIMC7_ROUNDS: usize = 91;
const SPONGE_SEED: &[u8] = b"mimcsponge";
const SPONGE_ROUNDS: usize = 220;

fn to_fr(x: &U256) -> Result<u256, ZkError> {
    let bytes = x.to_be_bytes();
    if bytes.len() != 32 {
        return Err(ZkError::InvalidInput);
    }
    let mut buf = [0u8; 32];
    bytes.copy_into_slice(&mut buf);
    let v = u256::from_be_bytes(buf);
    if v >= Bn254::FR_MODULUS {
        return Err(ZkError::InvalidInput);
    }
    Ok(v)
}

fn from_fr(env: &Env, v: u256) -> U256 {
    U256::from_be_bytes(env, &Bytes::from_array(env, &v.to_be_bytes()))
}

/// circomlibjs `getConstants`: cts[0] = 0, then a Keccak chain reduced mod r.
/// When `zero_last` is set the final constant is also 0 (MiMCSponge).
fn round_constants<const N: usize>(env: &Env, seed: &[u8], zero_last: bool) -> [u256; N] {
    let mut cts = [u256::ZERO; N];
    let mut c = env
        .crypto()
        .keccak256(&Bytes::from_slice(env, seed))
        .to_array();
    let end = if zero_last { N.saturating_sub(1) } else { N };
    for slot in cts.iter_mut().take(end).skip(1) {
        c = env
            .crypto()
            .keccak256(&Bytes::from_array(env, &c))
            .to_array();
        *slot = u256::from_be_bytes(c) % Bn254::FR_MODULUS;
    }
    cts
}

fn pow7(x: u256) -> u256 {
    let x2 = Bn254::mul(x, x);
    let x4 = Bn254::mul(x2, x2);
    let x6 = Bn254::mul(x4, x2);
    Bn254::mul(x6, x)
}

fn pow5(x: u256) -> u256 {
    let x2 = Bn254::mul(x, x);
    let x4 = Bn254::mul(x2, x2);
    Bn254::mul(x4, x)
}

fn mimc7_permute(cts: &[u256], x_in: u256, k: u256) -> u256 {
    let mut x = x_in;
    for c in cts {
        let t = Bn254::add(Bn254::add(x, k), *c);
        x = pow7(t);
    }
    Bn254::add(x, k)
}

fn feistel(cts: &[u256], xl_in: u256, xr_in: u256, k: u256) -> (u256, u256) {
    let mut xl = xl_in;
    let mut xr = xr_in;
    let last = cts.len().saturating_sub(1);
    for (i, c) in cts.iter().enumerate() {
        let t = Bn254::add(Bn254::add(xl, k), *c);
        let tmp = xr;
        if i < last {
            xr = xl;
            xl = Bn254::add(tmp, pow5(t));
        } else {
            xr = Bn254::add(tmp, pow5(t));
        }
    }
    (xl, xr)
}

/// MiMC-7 block cipher `hash(x, k)` (circomlibjs `mimc7.hash`).
pub fn mimc7(env: &Env, x: &U256, k: &U256) -> Result<U256, ZkError> {
    let (x, k) = (to_fr(x)?, to_fr(k)?);
    let cts = round_constants::<MIMC7_ROUNDS>(env, MIMC7_SEED, false);
    Ok(from_fr(env, mimc7_permute(&cts, x, k)))
}

/// circomlibjs `mimc7.multiHash(arr, key)`: `r = r + x + hash(x, r)`.
pub fn mimc7_multi(env: &Env, inputs: &[U256], key: &U256) -> Result<U256, ZkError> {
    let mut r = to_fr(key)?;
    let cts = round_constants::<MIMC7_ROUNDS>(env, MIMC7_SEED, false);
    for input in inputs {
        let x = to_fr(input)?;
        r = Bn254::add(Bn254::add(r, x), mimc7_permute(&cts, x, r));
    }
    Ok(from_fr(env, r))
}

/// circomlibjs `mimcsponge.hash(xL, xR, k)` (one Feistel permutation).
pub fn mimc_feistel(
    env: &Env,
    xl: &U256,
    xr: &U256,
    k: &U256,
) -> Result<(U256, U256), ZkError> {
    let (xl, xr, k) = (to_fr(xl)?, to_fr(xr)?, to_fr(k)?);
    let cts = round_constants::<SPONGE_ROUNDS>(env, SPONGE_SEED, true);
    let (l, r) = feistel(&cts, xl, xr, k);
    Ok((from_fr(env, l), from_fr(env, r)))
}

/// circomlibjs `mimcsponge.multiHash(arr, key, numOutputs)`.
pub fn mimc_feistel_sponge(
    env: &Env,
    inputs: &[U256],
    key: &U256,
    n_outputs: u32,
) -> Result<Vec<U256>, ZkError> {
    if n_outputs == 0 {
        return Err(ZkError::InvalidInput);
    }
    let k = to_fr(key)?;
    let cts = round_constants::<SPONGE_ROUNDS>(env, SPONGE_SEED, true);
    let mut r = u256::ZERO;
    let mut c = u256::ZERO;
    for input in inputs {
        r = Bn254::add(r, to_fr(input)?);
        let (l, nc) = feistel(&cts, r, c, k);
        r = l;
        c = nc;
    }
    let mut out = Vec::new(env);
    out.push_back(from_fr(env, r));
    for _ in 1..n_outputs {
        let (l, nc) = feistel(&cts, r, c, k);
        r = l;
        c = nc;
        out.push_back(from_fr(env, r));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env() -> Env {
        let e = Env::default();
        e.cost_estimate().budget().reset_unlimited();
        e
    }

    fn dec(env: &Env, s: &str) -> U256 {
        from_fr(env, u256::from_str_radix(s, 10).unwrap())
    }

    fn n(env: &Env, v: u128) -> U256 {
        U256::from_u128(env, v)
    }

    #[test]
    fn mimc7_hash_matches_circomlib() {
        let env = env();
        let h = mimc7(&env, &n(&env, 12), &n(&env, 45)).unwrap();
        assert_eq!(
            h,
            dec(
                &env,
                "19746142529723647765530752502670948774458299263315590587358840390982005703908"
            )
        );
    }

    #[test]
    fn mimc7_multihash_matches_circomlib() {
        let env = env();
        let zero = n(&env, 0);
        let cases: [(&[u128], &str); 4] = [
            (
                &[12],
                "16051049095595290701999129793867590386356047218708919933694064829788708231421",
            ),
            (
                &[78, 41],
                "2938611815373543102852102540059918590261345652613741345181300284995514063984",
            ),
            (
                &[12, 45],
                "9949998637984578981906561631883120271399801229641312099559043216173958006905",
            ),
            (
                &[12, 45, 78, 41],
                "18226366069841799622585958305961373004333097209608110160936134895615261821931",
            ),
        ];
        for (ins, expected) in cases {
            let mut v = soroban_sdk::vec![&env];
            for x in ins {
                v.push_back(n(&env, *x));
            }
            let arr: [U256; 4];
            let slice: &[U256] = {
                let mut tmp = [n(&env, 0), n(&env, 0), n(&env, 0), n(&env, 0)];
                for (i, x) in v.iter().enumerate() {
                    tmp[i] = x;
                }
                arr = tmp;
                &arr[..v.len() as usize]
            };
            assert_eq!(mimc7_multi(&env, slice, &zero).unwrap(), dec(&env, expected));
        }
    }

    #[test]
    fn feistel_matches_circomlib() {
        let env = env();
        let (l, r) = mimc_feistel(&env, &n(&env, 1), &n(&env, 2), &n(&env, 3)).unwrap();
        assert_eq!(
            l,
            dec(
                &env,
                "6708731823698495319568907590961715813245439042144756682443964812580711632283"
            )
        );
        assert_eq!(
            r,
            dec(
                &env,
                "18444058245820418255538785847032978363886102372504864086197416499869253008979"
            )
        );
    }

    #[test]
    fn sponge_first_output_matches_circomlib() {
        let env = env();
        let out =
            mimc_feistel_sponge(&env, &[n(&env, 1), n(&env, 2)], &n(&env, 0), 3).unwrap();
        assert_eq!(out.len(), 3);
        assert_eq!(
            out.get(0).unwrap(),
            dec(
                &env,
                "6432874992294674054175660886639983161951588679049969118759985614991668008078"
            )
        );
    }

    #[test]
    fn rejects_non_canonical_input() {
        let env = env();
        let big = from_fr(&env, Bn254::FR_MODULUS - u256::ONE);
        assert!(mimc7(&env, &big, &n(&env, 0)).is_ok());
        let bad = U256::from_be_bytes(&env, &Bytes::from_array(&env, &[0xff; 32]));
        assert_eq!(mimc7(&env, &bad, &n(&env, 0)), Err(ZkError::InvalidInput));
        assert_eq!(
            mimc7_multi(&env, &[bad.clone()], &n(&env, 0)),
            Err(ZkError::InvalidInput)
        );
        assert_eq!(
            mimc_feistel_sponge(&env, &[bad], &n(&env, 0), 1),
            Err(ZkError::InvalidInput)
        );
    }

    #[test]
    fn sponge_rejects_zero_outputs() {
        let env = env();
        assert_eq!(
            mimc_feistel_sponge(&env, &[n(&env, 1)], &n(&env, 0), 0),
            Err(ZkError::InvalidInput)
        );
    }
}