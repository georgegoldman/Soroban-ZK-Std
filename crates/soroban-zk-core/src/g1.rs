use ark_bn254::{Fr, G1Projective};
use ark_ec::Group;
use core::ops::{Add, Mul};
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct G1(pub G1Projective);
impl G1 {
    pub fn identity() -> Self {
        Self(G1Projective::identity())
    }
    pub fn generator() -> Self {
        Self(G1Projective::generator())
    }
    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }
    pub fn to_affine(&self) -> ark_bn254::G1Affine {
        self.0.into()
    }
}
impl Add for G1 {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Self(self.0 + rhs.0)
    }
}
impl Mul<Fr> for G1 {
    type Output = Self;
    fn mul(self, rhs: Fr) -> Self {
        Self(self.0 * rhs)
    }
}
