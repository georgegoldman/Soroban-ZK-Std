//! JSON artifact parsers: SnarkJS and gnark Groth16 verifying keys, SnarkJS
//! proofs and public-input files.
//!
//! # G2 coordinate order
//!
//! SnarkJS writes every Fq2 element as `[c0, c1]` (real, imaginary), and gnark
//! writes it as `{"A0": c0, "A1": c1}`. Both map directly onto the `(c0, c1)`
//! tuple of `soroban_zk_std::G2Affine`; no swap happens while parsing. The
//! EIP-197 wire order (`c1 || c0`) is only applied when a proof is serialized
//! to bytes (see [`crate::bn254::G2::to_bytes`]). This was checked against the
//! repository's real SnarkJS key and proof (shielded-asset-template): the
//! `[c0, c1]` reading is on the curve and verifies, the swapped reading is not.

use serde_json::{Map, Value};

use crate::bn254::{self, G1, G2};

/// A Groth16 verifying key over BN254, fully validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyingKey {
    pub alpha_g1: G1,
    pub beta_g2: G2,
    pub gamma_g2: G2,
    pub delta_g2: G2,
    pub ic: Vec<G1>,
}

/// A Groth16 proof over BN254, fully validated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Proof {
    pub a: G1,
    pub b: G2,
    pub c: G1,
}

impl Proof {
    /// `A (64) || B (128, EIP-197) || C (64)`: the exact buffer
    /// `soroban_zk_std::Groth16Proof::from_bytes` accepts.
    pub fn to_bytes(&self) -> [u8; 256] {
        let mut out = [0u8; 256];
        out[..64].copy_from_slice(&self.a.to_bytes());
        out[64..192].copy_from_slice(&self.b.to_bytes());
        out[192..].copy_from_slice(&self.c.to_bytes());
        out
    }

    /// Decodes and validates a 256-byte proof buffer.
    pub fn from_bytes(b: &[u8]) -> Result<Self, String> {
        if b.len() != 256 {
            return Err(format!("proof buffer must be 256 bytes, found {}", b.len()));
        }
        Ok(Self {
            a: bn254::g1_from_bytes(&b[..64], "A")?,
            b: bn254::g2_from_bytes(&b[64..192], "B")?,
            c: bn254::g1_from_bytes(&b[192..], "C")?,
        })
    }
}

/// Input format for `import-vk`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VkFormat {
    Snarkjs,
    Gnark,
}

impl VkFormat {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.to_ascii_lowercase().as_str() {
            "snarkjs" => Ok(Self::Snarkjs),
            "gnark" => Ok(Self::Gnark),
            "noir" => Err("format `noir` is not supported yet (only snarkjs and gnark)".into()),
            other => Err(format!(
                "unknown --format `{other}` (expected `snarkjs` or `gnark`)"
            )),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Snarkjs => "snarkjs",
            Self::Gnark => "gnark",
        }
    }
}

/// What kind of artifact a JSON document is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    SnarkjsVk,
    GnarkVk,
    SnarkjsProof,
    PublicInputs,
}

impl Kind {
    pub fn describe(self) -> &'static str {
        match self {
            Self::SnarkjsVk => "SnarkJS Groth16 verifying key (BN254)",
            Self::GnarkVk => "gnark Groth16 verifying key (BN254)",
            Self::SnarkjsProof => "SnarkJS Groth16 proof (BN254)",
            Self::PublicInputs => "public inputs (BN254 scalars)",
        }
    }
}

/// Detects the artifact type. Errors on unsupported curves (e.g. BLS12-381)
/// and on documents that look like none of the supported artifacts.
pub fn detect(v: &Value) -> Result<Kind, String> {
    check_curve(v)?;
    match v {
        Value::Array(_) => Ok(Kind::PublicInputs),
        Value::Object(m) if m.contains_key("vk_alpha_1") => Ok(Kind::SnarkjsVk),
        Value::Object(m) if m.contains_key("pi_a") => Ok(Kind::SnarkjsProof),
        Value::Object(m) if m.contains_key("G1") && m.contains_key("G2") => Ok(Kind::GnarkVk),
        _ => Err(
            "unrecognised file: expected a SnarkJS verification key / proof, \
                  a gnark verifying key, a public-inputs array, or a hex proof"
                .into(),
        ),
    }
}

/// Rejects a declared curve other than BN254 with a clear message.
pub fn check_curve(v: &Value) -> Result<(), String> {
    if let Some(curve) = v.get("curve").and_then(Value::as_str) {
        let c = curve.to_ascii_lowercase();
        if c.contains("bls12") {
            return Err(format!(
                "curve `{curve}` is not supported: only BN254 (`bn128` / `bn254`) is supported"
            ));
        }
        if c != "bn128" && c != "bn254" && c != "alt_bn128" {
            return Err(format!(
                "curve `{curve}` is not supported: only BN254 (`bn128` / `bn254`) is supported"
            ));
        }
    }
    if let Some(protocol) = v.get("protocol").and_then(Value::as_str) {
        if protocol != "groth16" {
            return Err(format!(
                "protocol `{protocol}` is not supported: only `groth16` is supported"
            ));
        }
    }
    Ok(())
}

fn field<'a>(v: &'a Value, key: &str, ctx: &str) -> Result<&'a Value, String> {
    v.get(key)
        .ok_or_else(|| format!("{ctx}: missing the `{key}` field"))
}

fn array<'a>(v: &'a Value, what: &str) -> Result<&'a Vec<Value>, String> {
    v.as_array()
        .ok_or_else(|| format!("{what}: expected a JSON array"))
}

fn is_int(v: &Value, n: u64) -> bool {
    bn254::parse_uint(v, "").ok()
        == Some({
            let mut b = [0u8; 32];
            b[24..].copy_from_slice(&n.to_be_bytes());
            b
        })
}

/// SnarkJS G1: `["x", "y", "1"]` (the projective `z` must be 1).
pub fn snarkjs_g1(v: &Value, what: &str) -> Result<G1, String> {
    let c = array(v, what)?;
    if c.len() != 2 && c.len() != 3 {
        return Err(format!(
            "{what}: expected a G1 point [x, y, \"1\"], found {} values",
            c.len()
        ));
    }
    if c.len() == 3 && !is_int(&c[2], 1) {
        return Err(format!(
            "{what}: expected an affine point with z = \"1\" (points at infinity are not allowed)"
        ));
    }
    let x = bn254::parse_uint(&c[0], &format!("{what}[0]"))?;
    let y = bn254::parse_uint(&c[1], &format!("{what}[1]"))?;
    bn254::g1(x, y, what)
}

fn snarkjs_fq2(v: &Value, what: &str) -> Result<([u8; 32], [u8; 32]), String> {
    let c = array(v, what)?;
    if c.len() != 2 {
        return Err(format!(
            "{what}: expected an Fq2 element [c0, c1], found {} values",
            c.len()
        ));
    }
    Ok((
        bn254::parse_uint(&c[0], &format!("{what}[0]"))?,
        bn254::parse_uint(&c[1], &format!("{what}[1]"))?,
    ))
}

/// SnarkJS G2: `[[x.c0, x.c1], [y.c0, y.c1], ["1", "0"]]`.
pub fn snarkjs_g2(v: &Value, what: &str) -> Result<G2, String> {
    let c = array(v, what)?;
    if c.len() != 2 && c.len() != 3 {
        return Err(format!(
            "{what}: expected a G2 point [[x.c0, x.c1], [y.c0, y.c1], [\"1\", \"0\"]], found {} values",
            c.len()
        ));
    }
    if c.len() == 3 {
        let z = array(&c[2], &format!("{what}[2]"))?;
        if z.len() != 2 || !is_int(&z[0], 1) || !is_int(&z[1], 0) {
            return Err(format!(
                "{what}: expected an affine point with z = [\"1\", \"0\"]"
            ));
        }
    }
    let x = snarkjs_fq2(&c[0], &format!("{what}[0]"))?;
    let y = snarkjs_fq2(&c[1], &format!("{what}[1]"))?;
    bn254::g2(x, y, what)
}

/// gnark G1 (`encoding/json` of `bn254.G1Affine`): `{"X": .., "Y": ..}`.
pub fn gnark_g1(v: &Value, what: &str) -> Result<G1, String> {
    let x = bn254::parse_uint(field(v, "X", what)?, &format!("{what}.X"))?;
    let y = bn254::parse_uint(field(v, "Y", what)?, &format!("{what}.Y"))?;
    bn254::g1(x, y, what)
}

fn gnark_e2(v: &Value, what: &str) -> Result<([u8; 32], [u8; 32]), String> {
    Ok((
        bn254::parse_uint(field(v, "A0", what)?, &format!("{what}.A0"))?,
        bn254::parse_uint(field(v, "A1", what)?, &format!("{what}.A1"))?,
    ))
}

/// gnark G2 (`bn254.G2Affine`): `{"X": {"A0": c0, "A1": c1}, "Y": {..}}`.
pub fn gnark_g2(v: &Value, what: &str) -> Result<G2, String> {
    let x = gnark_e2(field(v, "X", what)?, &format!("{what}.X"))?;
    let y = gnark_e2(field(v, "Y", what)?, &format!("{what}.Y"))?;
    bn254::g2(x, y, what)
}

/// One named point of a verifying key, for per-item diagnostics.
pub enum PointRef<'a> {
    G1(&'a Value),
    G2(&'a Value),
}

/// Lists every point of a verifying key with its name, so `inspect` can
/// report each one. Structural errors (missing fields) are returned as `Err`.
pub fn vk_points<'a>(
    v: &'a Value,
    format: VkFormat,
) -> Result<Vec<(String, PointRef<'a>)>, String> {
    let mut out = Vec::new();
    match format {
        VkFormat::Snarkjs => {
            let ctx = "verification key";
            out.push((
                "vk_alpha_1".into(),
                PointRef::G1(field(v, "vk_alpha_1", ctx)?),
            ));
            for k in ["vk_beta_2", "vk_gamma_2", "vk_delta_2"] {
                out.push((k.into(), PointRef::G2(field(v, k, ctx)?)));
            }
            let ic = array(field(v, "IC", ctx)?, "IC")?;
            if ic.is_empty() {
                return Err("IC: must contain at least one point".into());
            }
            for (i, p) in ic.iter().enumerate() {
                out.push((format!("IC[{i}]"), PointRef::G1(p)));
            }
        }
        VkFormat::Gnark => {
            let g1 = field(v, "G1", "verifying key")?;
            let g2 = field(v, "G2", "verifying key")?;
            out.push(("G1.Alpha".into(), PointRef::G1(field(g1, "Alpha", "G1")?)));
            for k in ["Beta", "Delta"] {
                if let Some(p) = g1.get(k) {
                    out.push((format!("G1.{k}"), PointRef::G1(p)));
                }
            }
            for k in ["Beta", "Gamma", "Delta"] {
                out.push((format!("G2.{k}"), PointRef::G2(field(g2, k, "G2")?)));
            }
            let k = array(field(g1, "K", "G1")?, "G1.K")?;
            if k.is_empty() {
                return Err("G1.K: must contain at least one point".into());
            }
            for (i, p) in k.iter().enumerate() {
                out.push((format!("G1.K[{i}]"), PointRef::G1(p)));
            }
            if let Some(ck) = v.get("CommitmentKeys").and_then(Value::as_array) {
                if !ck.is_empty() {
                    return Err("CommitmentKeys: gnark Pedersen commitment extensions \
                                are not supported by soroban_zk_std::groth16_verify"
                        .into());
                }
            }
        }
    }
    Ok(out)
}

/// Validates one listed point.
pub fn check_point(name: &str, p: &PointRef<'_>, format: VkFormat) -> Result<(), String> {
    match (p, format) {
        (PointRef::G1(v), VkFormat::Snarkjs) => snarkjs_g1(v, name).map(|_| ()),
        (PointRef::G2(v), VkFormat::Snarkjs) => snarkjs_g2(v, name).map(|_| ()),
        (PointRef::G1(v), VkFormat::Gnark) => gnark_g1(v, name).map(|_| ()),
        (PointRef::G2(v), VkFormat::Gnark) => gnark_g2(v, name).map(|_| ()),
    }
}

/// Parses and validates a verifying key in the given format.
pub fn parse_vk(v: &Value, format: VkFormat) -> Result<VerifyingKey, String> {
    if !v.is_object() {
        return Err("verifying key must be a JSON object".into());
    }
    check_curve(v)?;
    let vk = match format {
        VkFormat::Snarkjs => {
            if v.get("vk_alpha_1").is_none() && v.get("G1").is_some() {
                return Err("this looks like a gnark key; use --format gnark".into());
            }
            let ic = array(field(v, "IC", "verification key")?, "IC")?
                .iter()
                .enumerate()
                .map(|(i, p)| snarkjs_g1(p, &format!("IC[{i}]")))
                .collect::<Result<Vec<_>, _>>()?;
            let ctx = "verification key";
            VerifyingKey {
                alpha_g1: snarkjs_g1(field(v, "vk_alpha_1", ctx)?, "vk_alpha_1")?,
                beta_g2: snarkjs_g2(field(v, "vk_beta_2", ctx)?, "vk_beta_2")?,
                gamma_g2: snarkjs_g2(field(v, "vk_gamma_2", ctx)?, "vk_gamma_2")?,
                delta_g2: snarkjs_g2(field(v, "vk_delta_2", ctx)?, "vk_delta_2")?,
                ic,
            }
        }
        VkFormat::Gnark => {
            if v.get("vk_alpha_1").is_some() {
                return Err("this looks like a SnarkJS key; use --format snarkjs".into());
            }
            // Validate every point, including the optional G1.Beta / G1.Delta
            // and the commitment-key guard.
            for (name, p) in vk_points(v, VkFormat::Gnark)? {
                check_point(&name, &p, VkFormat::Gnark)?;
            }
            let g1 = field(v, "G1", "verifying key")?;
            let g2 = field(v, "G2", "verifying key")?;
            let ic = array(field(g1, "K", "G1")?, "G1.K")?
                .iter()
                .enumerate()
                .map(|(i, p)| gnark_g1(p, &format!("G1.K[{i}]")))
                .collect::<Result<Vec<_>, _>>()?;
            VerifyingKey {
                alpha_g1: gnark_g1(field(g1, "Alpha", "G1")?, "G1.Alpha")?,
                beta_g2: gnark_g2(field(g2, "Beta", "G2")?, "G2.Beta")?,
                gamma_g2: gnark_g2(field(g2, "Gamma", "G2")?, "G2.Gamma")?,
                delta_g2: gnark_g2(field(g2, "Delta", "G2")?, "G2.Delta")?,
                ic,
            }
        }
    };
    if vk.ic.is_empty() {
        return Err("IC: must contain at least one point".into());
    }
    if let Some(n) = v.get("nPublic") {
        let n = n
            .as_u64()
            .ok_or_else(|| "nPublic: expected a non-negative integer".to_string())?;
        if n as usize + 1 != vk.ic.len() {
            return Err(format!(
                "nPublic is {n} but IC has {} points (expected nPublic + 1)",
                vk.ic.len()
            ));
        }
    }
    Ok(vk)
}

/// Parses and validates a SnarkJS `proof.json`.
pub fn parse_snarkjs_proof(v: &Value) -> Result<Proof, String> {
    let m: &Map<String, Value> = v
        .as_object()
        .ok_or_else(|| "proof must be a JSON object".to_string())?;
    check_curve(v)?;
    let get = |k: &str| {
        m.get(k)
            .ok_or_else(|| format!("proof: missing the `{k}` field"))
    };
    Ok(Proof {
        a: snarkjs_g1(get("pi_a")?, "pi_a")?,
        b: snarkjs_g2(get("pi_b")?, "pi_b")?,
        c: snarkjs_g1(get("pi_c")?, "pi_c")?,
    })
}

/// Parses a SnarkJS `public.json` (an array of decimal strings) into 32-byte
/// big-endian scalars, rejecting any value `>= r`.
pub fn parse_public_inputs(v: &Value) -> Result<Vec<[u8; 32]>, String> {
    let items = v
        .as_array()
        .ok_or_else(|| "public inputs must be a JSON array of integer strings".to_string())?;
    items
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let what = format!("public[{i}]");
            let be = bn254::parse_uint(s, &what)?;
            bn254::check_scalar(&be, &what)?;
            Ok(be)
        })
        .collect()
}
