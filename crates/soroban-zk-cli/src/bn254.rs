//! Offline BN254 checks used by every command.
//!
//! Field elements are kept as 32-byte big-endian arrays (the encoding used by
//! `soroban_zk_std` and EIP-196/197). Validation goes through arkworks:
//! canonical (`< p` / `< r`), on-curve, and G2 prime-order subgroup checks.

use ark_bn254::{Fq, Fq2, Fr, G1Affine as ArkG1, G2Affine as ArkG2};
use ark_ff::{BigInt, PrimeField};
use serde_json::Value;

/// BN254 base-field modulus `p`, big-endian hex.
pub const P_HEX: &str = "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47";
/// BN254 scalar-field modulus `r`, big-endian hex.
pub const R_HEX: &str = "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001";

/// An affine G1 point (`x`, `y` big-endian), already validated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct G1 {
    pub x: [u8; 32],
    pub y: [u8; 32],
}

/// An affine G2 point, already validated. Coordinates are `(c0, c1)` =
/// (real, imaginary), the `soroban_zk_std::G2Affine` tuple order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct G2 {
    pub x: ([u8; 32], [u8; 32]),
    pub y: ([u8; 32], [u8; 32]),
}

impl G1 {
    /// `x || y`, 64 bytes.
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.x);
        out[32..].copy_from_slice(&self.y);
        out
    }
}

impl G2 {
    /// EIP-197 wire order `x.c1 || x.c0 || y.c1 || y.c0`, 128 bytes. This is
    /// the layout `Groth16Proof::from_bytes` reads.
    pub fn to_bytes(&self) -> [u8; 128] {
        let mut out = [0u8; 128];
        out[..32].copy_from_slice(&self.x.1);
        out[32..64].copy_from_slice(&self.x.0);
        out[64..96].copy_from_slice(&self.y.1);
        out[96..].copy_from_slice(&self.y.0);
        out
    }
}

/// Parses a non-negative integer from a JSON value: a decimal string (the
/// SnarkJS / gnark default), a `0x` hex string, or a JSON integer.
pub fn parse_uint(v: &Value, what: &str) -> Result<[u8; 32], String> {
    match v {
        Value::String(s) => parse_uint_str(s.trim())
            .ok_or_else(|| format!("{what}: `{s}` is not a valid 256-bit unsigned integer")),
        Value::Number(n) => n.as_u64().map(u64_to_be).ok_or_else(|| {
            format!("{what}: `{n}` is not a non-negative integer (use a decimal string)")
        }),
        other => Err(format!(
            "{what}: expected an integer string, found {}",
            kind(other)
        )),
    }
}

fn u64_to_be(n: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&n.to_be_bytes());
    out
}

/// Parses a decimal or `0x`-prefixed hex string into 32 big-endian bytes.
/// Returns `None` on an empty string, a bad digit, or a value `>= 2^256`.
pub fn parse_uint_str(s: &str) -> Option<[u8; 32]> {
    let (digits, radix) = match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(h) => (h, 16u32),
        None => (s, 10u32),
    };
    if digits.is_empty() {
        return None;
    }
    let mut out = [0u8; 32];
    for ch in digits.chars() {
        let d = ch.to_digit(radix)?;
        // out = out * radix + d
        let mut carry = d;
        for byte in out.iter_mut().rev() {
            let v = u32::from(*byte) * radix + carry;
            *byte = (v & 0xff) as u8;
            carry = v >> 8;
        }
        if carry != 0 {
            return None;
        }
    }
    Some(out)
}

/// Decodes a hex string (optional `0x`, surrounding whitespace ignored).
pub fn decode_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in bytes.chunks(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
    }
    Some(out)
}

/// Lower-case hex encoding without a prefix.
pub fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 0xf) as usize] as char);
    }
    s
}

fn kind(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}

fn to_bigint(be: &[u8; 32]) -> BigInt<4> {
    let mut limbs = [0u64; 4];
    for (i, limb) in limbs.iter_mut().enumerate() {
        let start = 32 - 8 * (i + 1);
        let mut w = [0u8; 8];
        w.copy_from_slice(&be[start..start + 8]);
        *limb = u64::from_be_bytes(w);
    }
    BigInt::new(limbs)
}

/// A canonical base-field element (`< p`).
pub fn fq(be: &[u8; 32], what: &str) -> Result<Fq, String> {
    Fq::from_bigint(to_bigint(be))
        .ok_or_else(|| format!("{what}: not a canonical BN254 base-field element (must be < p)"))
}

/// A canonical scalar (`< r`).
pub fn check_scalar(be: &[u8; 32], what: &str) -> Result<(), String> {
    Fr::from_bigint(to_bigint(be))
        .map(|_| ())
        .ok_or_else(|| format!("{what}: scalar is not < r (BN254 scalar-field modulus 0x{R_HEX})"))
}

/// Validates an affine G1 point: canonical coordinates, not the identity, on
/// `y^2 = x^3 + 3`. G1 has cofactor 1, so on-curve implies in-subgroup.
pub fn g1(x: [u8; 32], y: [u8; 32], what: &str) -> Result<G1, String> {
    let fx = fq(&x, &format!("{what}.x"))?;
    let fy = fq(&y, &format!("{what}.y"))?;
    if x == [0u8; 32] && y == [0u8; 32] {
        return Err(format!("{what}: point at infinity is not allowed here"));
    }
    if !ArkG1::new_unchecked(fx, fy).is_on_curve() {
        return Err(format!(
            "{what}: not on the BN254 G1 curve (y^2 != x^3 + 3)"
        ));
    }
    Ok(G1 { x, y })
}

/// Validates an affine G2 point given as `(c0, c1)` pairs: canonical
/// coordinates, on the twist curve, and in the prime-order subgroup.
pub fn g2(x: ([u8; 32], [u8; 32]), y: ([u8; 32], [u8; 32]), what: &str) -> Result<G2, String> {
    let fx = Fq2::new(
        fq(&x.0, &format!("{what}.x.c0"))?,
        fq(&x.1, &format!("{what}.x.c1"))?,
    );
    let fy = Fq2::new(
        fq(&y.0, &format!("{what}.y.c0"))?,
        fq(&y.1, &format!("{what}.y.c1"))?,
    );
    if [x.0, x.1, y.0, y.1].iter().all(|c| *c == [0u8; 32]) {
        return Err(format!("{what}: point at infinity is not allowed here"));
    }
    let p = ArkG2::new_unchecked(fx, fy);
    if !p.is_on_curve() {
        let swapped = ArkG2::new_unchecked(Fq2::new(fx.c1, fx.c0), Fq2::new(fy.c1, fy.c0));
        let hint = if swapped.is_on_curve() {
            " (its c0/c1 look swapped: expected [c0, c1] = [real, imaginary], \
             not the EIP-197 / Solidity calldata order [c1, c0])"
        } else {
            ""
        };
        return Err(format!("{what}: not on the BN254 G2 curve{hint}"));
    }
    if !p.is_in_correct_subgroup_assuming_on_curve() {
        return Err(format!(
            "{what}: on the curve but not in the G2 prime-order subgroup"
        ));
    }
    Ok(G2 { x, y })
}

/// Decodes and validates a G1 point from 64 big-endian bytes (`x || y`).
pub fn g1_from_bytes(b: &[u8], what: &str) -> Result<G1, String> {
    let (x, y) = (word(b, 0), word(b, 1));
    g1(x, y, what)
}

/// Decodes and validates a G2 point from 128 EIP-197 bytes
/// (`x.c1 || x.c0 || y.c1 || y.c0`).
pub fn g2_from_bytes(b: &[u8], what: &str) -> Result<G2, String> {
    g2((word(b, 1), word(b, 0)), (word(b, 3), word(b, 2)), what)
}

fn word(b: &[u8], i: usize) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&b[32 * i..32 * (i + 1)]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_decimal_and_hex() {
        let d = parse_uint_str("10000000").unwrap_or([0xff; 32]);
        let h = parse_uint_str("0x989680").unwrap_or([0xff; 32]);
        assert_eq!(d, h);
        assert_eq!(d[29..], [0x98, 0x96, 0x80]);
        assert!(parse_uint_str("").is_none());
        assert!(parse_uint_str("12a").is_none());
        assert!(parse_uint_str("-1").is_none());
        // 2^256 overflows.
        let two_256 =
            "115792089237316195423570985008687907853269984665640564039457584007913129639936";
        assert!(parse_uint_str(two_256).is_none());
    }

    #[test]
    fn hex_round_trip() {
        let bytes = [0u8, 1, 0xab, 0xff];
        assert_eq!(decode_hex(&encode_hex(&bytes)), Some(bytes.to_vec()));
        assert_eq!(decode_hex("0x0g"), None);
        assert_eq!(decode_hex("abc"), None);
    }

    #[test]
    fn generator_points_validate() {
        assert!(g1(u64_to_be(1), u64_to_be(2), "g").is_ok());
        assert!(g1(u64_to_be(1), u64_to_be(3), "g").is_err());
        assert!(g1([0; 32], [0; 32], "g").is_err());
    }

    #[test]
    fn scalar_bounds() {
        let r = parse_uint_str(&format!("0x{R_HEX}")).unwrap_or([0; 32]);
        assert!(check_scalar(&r, "s").is_err());
        let mut r_minus_1 = r;
        r_minus_1[31] -= 1;
        assert!(check_scalar(&r_minus_1, "s").is_ok());
        let p = parse_uint_str(&format!("0x{P_HEX}")).unwrap_or([0; 32]);
        assert!(fq(&p, "p").is_err());
    }
}
