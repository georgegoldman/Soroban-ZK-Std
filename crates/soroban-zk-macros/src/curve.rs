//! Minimal BN254 base-field (`Fq`, `Fq2`) arithmetic used at *compile time* to
//! validate verifying-key points before they are embedded in a contract.
//!
//! This code runs inside the proc-macro on the build host only. It favours
//! clarity over speed (affine formulas, inversion by Fermat), which is fine for
//! the handful of points in a verifying key.

use num_bigint::BigUint;

/// BN254 base-field modulus `p`.
const P_DEC: &str = "21888242871839275222246405745257275088696311157297823662689037894645226208583";
/// BN254 prime subgroup order `r`.
const R_DEC: &str = "21888242871839275222246405745257275088548364400416034343698204186575808495617";
/// Twist coefficient `b' = 3 / (9 + u)`, real part.
const B2_C0_DEC: &str =
    "19485874751759354771024239261021720505790618469301721065564631296452457478373";
/// Twist coefficient `b' = 3 / (9 + u)`, imaginary part.
const B2_C1_DEC: &str =
    "266929791119991161246907387137283842545076965332900288569378510910307636690";

fn dec(s: &str) -> BigUint {
    // The constants above are fixed, valid decimal literals; an empty value is
    // never produced, but avoid `unwrap` all the same.
    BigUint::parse_bytes(s.as_bytes(), 10).unwrap_or_default()
}

/// Shared field context (moduli and curve constants).
pub struct Bn254 {
    pub p: BigUint,
    r: BigUint,
    b2: Fq2,
}

/// An element `c0 + c1·u` of `Fq2 = Fq[u]/(u² + 1)`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Fq2 {
    pub c0: BigUint,
    pub c1: BigUint,
}

/// An affine G2 point, or `None` for the point at infinity.
type G2 = Option<(Fq2, Fq2)>;

impl Bn254 {
    pub fn new() -> Self {
        Self {
            p: dec(P_DEC),
            r: dec(R_DEC),
            b2: Fq2 {
                c0: dec(B2_C0_DEC),
                c1: dec(B2_C1_DEC),
            },
        }
    }

    // ── Fq ──────────────────────────────────────────────────────────────
    fn add(&self, a: &BigUint, b: &BigUint) -> BigUint {
        (a + b) % &self.p
    }
    fn sub(&self, a: &BigUint, b: &BigUint) -> BigUint {
        ((a + &self.p) - (b % &self.p)) % &self.p
    }
    fn mul(&self, a: &BigUint, b: &BigUint) -> BigUint {
        (a * b) % &self.p
    }
    fn inv(&self, a: &BigUint) -> BigUint {
        let e = &self.p - BigUint::from(2u8);
        a.modpow(&e, &self.p)
    }

    // ── Fq2 ─────────────────────────────────────────────────────────────
    fn f2_add(&self, a: &Fq2, b: &Fq2) -> Fq2 {
        Fq2 {
            c0: self.add(&a.c0, &b.c0),
            c1: self.add(&a.c1, &b.c1),
        }
    }
    fn f2_sub(&self, a: &Fq2, b: &Fq2) -> Fq2 {
        Fq2 {
            c0: self.sub(&a.c0, &b.c0),
            c1: self.sub(&a.c1, &b.c1),
        }
    }
    fn f2_mul(&self, a: &Fq2, b: &Fq2) -> Fq2 {
        // (a0 + a1 u)(b0 + b1 u) = (a0 b0 - a1 b1) + (a0 b1 + a1 b0) u
        let t0 = self.mul(&a.c0, &b.c0);
        let t1 = self.mul(&a.c1, &b.c1);
        Fq2 {
            c0: self.sub(&t0, &t1),
            c1: self.add(&self.mul(&a.c0, &b.c1), &self.mul(&a.c1, &b.c0)),
        }
    }
    fn f2_inv(&self, a: &Fq2) -> Fq2 {
        // 1 / (a0 + a1 u) = (a0 - a1 u) / (a0² + a1²)
        let norm = self.add(&self.mul(&a.c0, &a.c0), &self.mul(&a.c1, &a.c1));
        let n_inv = self.inv(&norm);
        Fq2 {
            c0: self.mul(&a.c0, &n_inv),
            c1: self.mul(&self.sub(&BigUint::default(), &a.c1), &n_inv),
        }
    }
    fn f2_is_zero(a: &Fq2) -> bool {
        a.c0 == BigUint::default() && a.c1 == BigUint::default()
    }
    fn f2_small(&self, n: u8) -> Fq2 {
        Fq2 {
            c0: BigUint::from(n),
            c1: BigUint::default(),
        }
    }

    // ── Curve checks ────────────────────────────────────────────────────

    /// `y² == x³ + 3` on G1. G1 has cofactor 1, so this also implies
    /// membership of the prime-order subgroup.
    pub fn g1_on_curve(&self, x: &BigUint, y: &BigUint) -> bool {
        let lhs = self.mul(y, y);
        let rhs = self.add(&self.mul(&self.mul(x, x), x), &BigUint::from(3u8));
        lhs == rhs
    }

    /// `y² == x³ + b'` on the sextic twist E'(Fq2).
    pub fn g2_on_curve(&self, x: &Fq2, y: &Fq2) -> bool {
        let lhs = self.f2_mul(y, y);
        let rhs = self.f2_add(&self.f2_mul(&self.f2_mul(x, x), x), &self.b2);
        lhs == rhs
    }

    fn g2_double(&self, p: &G2) -> G2 {
        let (x, y) = p.as_ref()?;
        if Self::f2_is_zero(y) {
            return None;
        }
        // λ = 3x² / 2y
        let num = self.f2_mul(&self.f2_small(3), &self.f2_mul(x, x));
        let den = self.f2_mul(&self.f2_small(2), y);
        let l = self.f2_mul(&num, &self.f2_inv(&den));
        let x3 = self.f2_sub(&self.f2_sub(&self.f2_mul(&l, &l), x), x);
        let y3 = self.f2_sub(&self.f2_mul(&l, &self.f2_sub(x, &x3)), y);
        Some((x3, y3))
    }

    fn g2_add(&self, a: &G2, b: &G2) -> G2 {
        let (x1, y1) = match a {
            Some(v) => v,
            None => return b.clone(),
        };
        let (x2, y2) = match b {
            Some(v) => v,
            None => return a.clone(),
        };
        if x1 == x2 {
            return if y1 == y2 { self.g2_double(a) } else { None };
        }
        let l = self.f2_mul(&self.f2_sub(y2, y1), &self.f2_inv(&self.f2_sub(x2, x1)));
        let x3 = self.f2_sub(&self.f2_sub(&self.f2_mul(&l, &l), x1), x2);
        let y3 = self.f2_sub(&self.f2_mul(&l, &self.f2_sub(x1, &x3)), y1);
        Some((x3, y3))
    }

    /// Prime-order subgroup membership on G2: `[r]P == O`.
    ///
    /// The twist has a large cofactor, so an on-curve point is *not*
    /// automatically in the subgroup; this check is what rejects
    /// small-subgroup / invalid-subgroup points.
    pub fn g2_in_subgroup(&self, x: &Fq2, y: &Fq2) -> bool {
        let base: G2 = Some((x.clone(), y.clone()));
        let mut acc: G2 = None;
        let bits = self.r.bits();
        for i in (0..bits).rev() {
            acc = self.g2_double(&acc);
            if self.r.bit(i) {
                acc = self.g2_add(&acc, &base);
            }
        }
        acc.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fq2(c0: &str, c1: &str) -> Fq2 {
        Fq2 {
            c0: dec(c0),
            c1: dec(c1),
        }
    }

    #[test]
    fn g2_generator_is_valid() {
        let c = Bn254::new();
        let x = fq2(
            "10857046999023057135944570762232829481370756359578518086990519993285655852781",
            "11559732032986387107991004021392285783925812861821192530917403151452391805634",
        );
        let y = fq2(
            "8495653923123431417604973247489272438418190587263600148770280649306958101930",
            "4082367875863433681332203403145435568316851327593401208105741076214120093531",
        );
        assert!(c.g2_on_curve(&x, &y));
        assert!(c.g2_in_subgroup(&x, &y));
        // Swapping c0/c1 (the EIP-197 wire order) must not be accepted as-is.
        let xs = Fq2 {
            c0: x.c1.clone(),
            c1: x.c0.clone(),
        };
        let ys = Fq2 {
            c0: y.c1.clone(),
            c1: y.c0.clone(),
        };
        assert!(!c.g2_on_curve(&xs, &ys));
    }

    #[test]
    fn g2_on_curve_point_outside_subgroup_is_rejected() {
        // x = 2 + u lies on the twist but outside the order-r subgroup.
        let c = Bn254::new();
        let x = fq2("2", "1");
        let y = fq2(
            "7292567877523311580221095596750716176434782432868683424513645834767876293070",
            "19659275751359636165940301690575149581329631496732780143538578556285923319774",
        );
        assert!(c.g2_on_curve(&x, &y));
        assert!(!c.g2_in_subgroup(&x, &y));
    }

    #[test]
    fn g1_generator_is_valid() {
        let c = Bn254::new();
        assert!(c.g1_on_curve(&BigUint::from(1u8), &BigUint::from(2u8)));
        assert!(!c.g1_on_curve(&BigUint::from(1u8), &BigUint::from(3u8)));
    }
}
