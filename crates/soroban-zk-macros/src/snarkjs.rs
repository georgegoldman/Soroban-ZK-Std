//! Compile-time parsing of SnarkJS `verification_key.json` files.
//!
//! SnarkJS (`snarkjs zkey export verificationkey`) emits every coordinate as a
//! decimal string and every point in projective form:
//!
//! ```json
//! "vk_alpha_1": ["<x>", "<y>", "1"],
//! "vk_beta_2":  [["<x.c0>", "<x.c1>"], ["<y.c0>", "<y.c1>"], ["1", "0"]],
//! "IC": [["<x>", "<y>", "1"], ...]
//! ```
//!
//! G2 coordinates in the JSON are `[c0, c1]` (real, imaginary), which is
//! exactly the `(c0, c1)` tuple order of `soroban_zk_std::G2Affine`. The
//! EIP-197 / CAP-0074 *wire* order (`c1 || c0`) is applied later by
//! `G2Affine::to_bytes`, so no swap happens here. A key whose `c0`/`c1` were
//! pre-swapped (e.g. copied from a Solidity verifier) fails the on-curve check
//! and is rejected with a diagnostic instead of being silently mis-encoded.

use num_bigint::BigUint;
use proc_macro2::TokenStream;
use quote::quote;
use serde_json::Value;

use crate::curve::{Bn254, Fq2};

/// A validated Groth16 verifying key, ready to be emitted as Rust tokens.
pub struct ParsedVk {
    alpha: (BigUint, BigUint),
    beta: (Fq2, Fq2),
    gamma: (Fq2, Fq2),
    delta: (Fq2, Fq2),
    ic: Vec<(BigUint, BigUint)>,
}

fn field<'a>(root: &'a Value, key: &str) -> Result<&'a Value, String> {
    root.get(key)
        .ok_or_else(|| format!("SnarkJS verifying key is missing the `{key}` field"))
}

fn array<'a>(v: &'a Value, what: &str) -> Result<&'a Vec<Value>, String> {
    v.as_array()
        .ok_or_else(|| format!("`{what}` must be a JSON array"))
}

/// Parses one coordinate: a decimal string (SnarkJS default), a `0x` hex
/// string, or a non-negative JSON integer. It must be a canonical field
/// element (`< p`).
fn fq(curve: &Bn254, v: &Value, what: &str) -> Result<BigUint, String> {
    let parsed = match v {
        Value::String(s) => {
            let s = s.trim();
            if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                BigUint::parse_bytes(hex.as_bytes(), 16)
            } else {
                BigUint::parse_bytes(s.as_bytes(), 10)
            }
        }
        Value::Number(n) => n.as_u64().map(BigUint::from),
        _ => None,
    };
    let value =
        parsed.ok_or_else(|| format!("`{what}` is not a valid non-negative integer: {v}"))?;
    if value >= curve.p {
        return Err(format!(
            "`{what}` is not a canonical BN254 base-field element (must be < p)"
        ));
    }
    Ok(value)
}

fn is_int(v: &Value, expected: u8) -> bool {
    match v {
        Value::String(s) => s.trim() == expected.to_string(),
        Value::Number(n) => n.as_u64() == Some(u64::from(expected)),
        _ => false,
    }
}

fn g1(curve: &Bn254, v: &Value, what: &str) -> Result<(BigUint, BigUint), String> {
    let coords = array(v, what)?;
    if coords.len() != 2 && coords.len() != 3 {
        return Err(format!(
            "`{what}` must be a G1 point `[x, y, \"1\"]`, found {} coordinates",
            coords.len()
        ));
    }
    if coords.len() == 3 && !is_int(&coords[2], 1) {
        return Err(format!(
            "`{what}` must be an affine point with z = \"1\" (points at infinity are not allowed in a verifying key)"
        ));
    }
    let x = fq(curve, &coords[0], &format!("{what}[0]"))?;
    let y = fq(curve, &coords[1], &format!("{what}[1]"))?;
    if !curve.g1_on_curve(&x, &y) {
        return Err(format!(
            "`{what}` is not on the BN254 G1 curve (y² != x³ + 3)"
        ));
    }
    Ok((x, y))
}

fn fq2(curve: &Bn254, v: &Value, what: &str) -> Result<Fq2, String> {
    let pair = array(v, what)?;
    if pair.len() != 2 {
        return Err(format!(
            "`{what}` must be an Fq2 element `[c0, c1]`, found {} values",
            pair.len()
        ));
    }
    Ok(Fq2 {
        c0: fq(curve, &pair[0], &format!("{what}[0]"))?,
        c1: fq(curve, &pair[1], &format!("{what}[1]"))?,
    })
}

fn g2(curve: &Bn254, v: &Value, what: &str) -> Result<(Fq2, Fq2), String> {
    let coords = array(v, what)?;
    if coords.len() != 2 && coords.len() != 3 {
        return Err(format!(
            "`{what}` must be a G2 point `[[x.c0, x.c1], [y.c0, y.c1], [\"1\", \"0\"]]`, found {} coordinates",
            coords.len()
        ));
    }
    if coords.len() == 3 {
        let z_ok = coords[2]
            .as_array()
            .map(|z| z.len() == 2 && is_int(&z[0], 1) && is_int(&z[1], 0))
            .unwrap_or(false);
        if !z_ok {
            return Err(format!(
                "`{what}` must be an affine point with z = [\"1\", \"0\"] (points at infinity are not allowed in a verifying key)"
            ));
        }
    }
    let x = fq2(curve, &coords[0], &format!("{what}[0]"))?;
    let y = fq2(curve, &coords[1], &format!("{what}[1]"))?;
    if !curve.g2_on_curve(&x, &y) {
        return Err(format!(
            "`{what}` is not on the BN254 G2 twist curve (y² != x³ + 3/(9+u)); \
             SnarkJS JSON stores G2 coordinates as [c0, c1] - check they were not pre-swapped into EIP-197 [c1, c0] order"
        ));
    }
    if !curve.g2_in_subgroup(&x, &y) {
        return Err(format!(
            "`{what}` is on the G2 twist curve but not in the prime-order subgroup ([r]P != O)"
        ));
    }
    Ok((x, y))
}

/// Parses and fully validates a SnarkJS Groth16 verifying key.
pub fn parse(json: &str) -> Result<ParsedVk, String> {
    let root: Value = serde_json::from_str(json)
        .map_err(|e| format!("malformed SnarkJS verifying key JSON: {e}"))?;
    if !root.is_object() {
        return Err("SnarkJS verifying key JSON must be an object".into());
    }
    if let Some(protocol) = root.get("protocol") {
        if protocol.as_str() != Some("groth16") {
            return Err(format!(
                "unsupported SnarkJS protocol {protocol}; only \"groth16\" verifying keys are supported"
            ));
        }
    }
    if let Some(curve) = root.get("curve") {
        let name = curve.as_str().unwrap_or_default().to_ascii_lowercase();
        if name != "bn128" && name != "bn254" {
            return Err(format!(
                "unsupported curve {curve}; only BN254 (SnarkJS \"bn128\") is supported"
            ));
        }
    }

    let curve = Bn254::new();
    let alpha = g1(&curve, field(&root, "vk_alpha_1")?, "vk_alpha_1")?;
    let beta = g2(&curve, field(&root, "vk_beta_2")?, "vk_beta_2")?;
    let gamma = g2(&curve, field(&root, "vk_gamma_2")?, "vk_gamma_2")?;
    let delta = g2(&curve, field(&root, "vk_delta_2")?, "vk_delta_2")?;

    let ic_json = array(field(&root, "IC")?, "IC")?;
    if ic_json.is_empty() {
        return Err("`IC` must contain at least one point (IC[0])".into());
    }
    let ic = ic_json
        .iter()
        .enumerate()
        .map(|(i, p)| g1(&curve, p, &format!("IC[{i}]")))
        .collect::<Result<Vec<_>, _>>()?;

    if let Some(n) = root.get("nPublic") {
        let expected = ic.len() - 1;
        if n.as_u64() != Some(expected as u64) {
            return Err(format!(
                "`nPublic` is {n} but `IC` has {} points (expected nPublic = {expected})",
                ic.len()
            ));
        }
    }

    Ok(ParsedVk {
        alpha,
        beta,
        gamma,
        delta,
        ic,
    })
}

fn u256_tokens(v: &BigUint) -> TokenStream {
    let mut bytes = [0u8; 32];
    let be = v.to_bytes_be();
    bytes[32 - be.len()..].copy_from_slice(&be);
    let mut hi = [0u8; 16];
    let mut lo = [0u8; 16];
    hi.copy_from_slice(&bytes[..16]);
    lo.copy_from_slice(&bytes[16..]);
    let hi = u128::from_be_bytes(hi);
    let lo = u128::from_be_bytes(lo);
    quote! { ::soroban_zk_std::__private::u256::from_words(#hi, #lo) }
}

fn g1_tokens((x, y): &(BigUint, BigUint)) -> TokenStream {
    let x = u256_tokens(x);
    let y = u256_tokens(y);
    quote! { ::soroban_zk_std::__private::G1Affine { x: #x, y: #y } }
}

fn g2_tokens((x, y): &(Fq2, Fq2)) -> TokenStream {
    let (x0, x1) = (u256_tokens(&x.c0), u256_tokens(&x.c1));
    let (y0, y1) = (u256_tokens(&y.c0), u256_tokens(&y.c1));
    quote! { ::soroban_zk_std::G2Affine { x: (#x0, #x1), y: (#y0, #y1) } }
}

impl ParsedVk {
    /// Emits a `const`-evaluable `Groth16VerifyingKey<'static>` expression.
    ///
    /// The `ic` slice is a promoted `'static` constant, so the key lives in
    /// the binary's read-only data with zero heap allocation.
    pub fn to_tokens(&self, track_file: Option<&str>) -> TokenStream {
        let alpha = g1_tokens(&self.alpha);
        let beta = g2_tokens(&self.beta);
        let gamma = g2_tokens(&self.gamma);
        let delta = g2_tokens(&self.delta);
        let ic = self.ic.iter().map(g1_tokens);
        // `include_bytes!` makes cargo rebuild the caller when the JSON changes.
        let track = track_file.map(|path| {
            quote! { const _: &[u8] = ::core::include_bytes!(#path); }
        });
        quote! {
            {
                #track
                const __SOROBAN_ZK_VK: ::soroban_zk_std::Groth16VerifyingKey<'static> =
                    ::soroban_zk_std::Groth16VerifyingKey {
                        alpha_g1: #alpha,
                        beta_g2: #beta,
                        gamma_g2: #gamma,
                        delta_g2: #delta,
                        ic: &[#(#ic),*],
                    };
                __SOROBAN_ZK_VK
            }
        }
    }
}
