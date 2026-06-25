use crate::{Bn254, G1Affine};
use core::convert::TryInto;
use ethnum::u256;

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

struct Sha256 {
    state: [u32; 8],
    buf: [u8; 64],
    buf_len: usize,
    total_len: u64,
}

impl Sha256 {
    fn new() -> Self {
        Self {
            state: H0,
            buf: [0u8; 64],
            buf_len: 0,
            total_len: 0,
        }
    }

    fn update(&mut self, data: &[u8]) {
        let mut offset = 0;
        if self.buf_len > 0 {
            let space = 64 - self.buf_len;
            let take = core::cmp::min(space, data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            offset += take;
            if self.buf_len == 64 {
                compress(&mut self.state, &self.buf);
                self.total_len += 64;
                self.buf_len = 0;
            }
        }
        while offset + 64 <= data.len() {
            let block: &[u8; 64] = data[offset..offset + 64].try_into().unwrap();
            compress(&mut self.state, block);
            self.total_len += 64;
            offset += 64;
        }
        if offset < data.len() {
            let remaining = data.len() - offset;
            self.buf[..remaining].copy_from_slice(&data[offset..]);
            self.buf_len = remaining;
        }
    }

    fn finalize(mut self) -> [u8; 32] {
        let total_bits = (self.total_len + self.buf_len as u64) * 8;
        self.buf[self.buf_len] = 0x80;
        if self.buf_len < 56 {
            for i in self.buf_len + 1..56 {
                self.buf[i] = 0;
            }
            self.buf[56..64].copy_from_slice(&total_bits.to_be_bytes());
            compress(&mut self.state, &self.buf);
        } else {
            for i in self.buf_len + 1..64 {
                self.buf[i] = 0;
            }
            compress(&mut self.state, &self.buf);
            let mut final_block = [0u8; 64];
            final_block[56..64].copy_from_slice(&total_bits.to_be_bytes());
            compress(&mut self.state, &final_block);
        }
        let mut out = [0u8; 32];
        for i in 0..8 {
            out[i * 4..(i + 1) * 4].copy_from_slice(&self.state[i].to_be_bytes());
        }
        out
    }
}

fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes(block[i * 4..(i + 1) * 4].try_into().unwrap());
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }

    let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) = (
        state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7],
    );

    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

#[cfg(test)]
fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize()
}

fn legendre_fq(a: u256) -> bool {
    if a == u256::from(0u8) {
        return false;
    }
    let res = Bn254::pow_mod(a, Bn254::LEGENDRE_EXP_FQ, Bn254::FQ_MODULUS);
    res == u256::from(1u8)
}

fn sqrt_fq(a: u256) -> u256 {
    if a == u256::from(0u8) {
        return u256::from(0u8);
    }
    let one = u256::from(1u8);
    let four = u256::from(4u8);
    let exp = (Bn254::FQ_MODULUS + one) / four;
    Bn254::pow_mod(a, exp, Bn254::FQ_MODULUS)
}

fn choose_y(_x: u256, y_sq: u256) -> u256 {
    let y = sqrt_fq(y_sq);
    if y & u256::from(1u8) == u256::from(0u8) {
        y
    } else {
        Bn254::sub_fq(Bn254::FQ_MODULUS, y)
    }
}

pub fn hash_to_field(msg: &[u8], counter: u64, dst: &[u8]) -> u256 {
    let mut h = Sha256::new();
    h.update(dst);
    h.update(msg);
    h.update(&counter.to_be_bytes());
    let digest = h.finalize();
    let val = u256::from_be_bytes(digest);
    if val < Bn254::FQ_MODULUS {
        val
    } else {
        val % Bn254::FQ_MODULUS
    }
}

pub fn try_and_increment(x: u256) -> Option<G1Affine> {
    if x >= Bn254::FQ_MODULUS {
        return None;
    }
    let x_sq = Bn254::mul_fq(x, x);
    let x_cb = Bn254::mul_fq(x_sq, x);
    let rhs = Bn254::add_fq(x_cb, Bn254::G1_B);
    if !legendre_fq(rhs) {
        return None;
    }
    let y = choose_y(x, rhs);
    if Bn254::is_valid_g1(x, y) {
        Some(G1Affine { x, y })
    } else {
        None
    }
}

pub fn hash_to_curve_g1(msg: &[u8], dst: &[u8]) -> G1Affine {
    let mut counter = 0u64;
    loop {
        let x = hash_to_field(msg, counter, dst);
        if let Some(point) = try_and_increment(x) {
            return point;
        }
        counter = counter.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_answer() {
        let digest = sha256(b"hello");
        let expected: [u8; 32] = [
            0x2c, 0xf2, 0x4d, 0xba, 0x5f, 0xb0, 0xa3, 0x0e, 0x26, 0xe8, 0x3b, 0x2a, 0xc5, 0xb9,
            0xe2, 0x9e, 0x1b, 0x16, 0x1e, 0x5c, 0x1f, 0xa7, 0x42, 0x5e, 0x73, 0x04, 0x33, 0x62,
            0x93, 0x8b, 0x98, 0x24,
        ];
        assert_eq!(digest, expected);
    }

    #[test]
    fn sha256_empty() {
        let digest = sha256(b"");
        let expected: [u8; 32] = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(digest, expected);
    }

    #[test]
    fn sha256_exact_block() {
        let input = [0x61u8; 55];
        let digest = sha256(&input);
        assert_ne!(digest, [0u8; 32]);
    }

    #[test]
    fn sha256_two_blocks() {
        let input = [0x61u8; 65];
        let digest = sha256(&input);
        assert_ne!(digest, [0u8; 32]);
    }

    #[test]
    fn sha256_incremental_vs_batched() {
        let data = b"incremental test data for SHA-256";
        let direct = sha256(data);
        let mut h = Sha256::new();
        h.update(b"incremental ");
        h.update(b"test data ");
        h.update(b"for SHA-256");
        let incremental = h.finalize();
        assert_eq!(direct, incremental);
    }

    #[test]
    fn hash_to_field_is_deterministic() {
        let a = hash_to_field(b"test", 0, b"domain");
        let b = hash_to_field(b"test", 0, b"domain");
        assert_eq!(a, b);
    }

    #[test]
    fn hash_to_field_different_counters() {
        let a = hash_to_field(b"test", 0, b"domain");
        let b = hash_to_field(b"test", 1, b"domain");
        assert_ne!(a, b);
    }

    #[test]
    fn hash_to_field_output_in_range() {
        let x = hash_to_field(b"test", 42, b"domain");
        assert!(x < Bn254::FQ_MODULUS);
    }

    #[test]
    fn hash_to_field_empty_msg() {
        let x = hash_to_field(b"", 0, b"domain");
        assert!(x < Bn254::FQ_MODULUS);
    }

    #[test]
    fn hash_to_field_uses_dst() {
        let a = hash_to_field(b"msg", 0, b"DST1");
        let b = hash_to_field(b"msg", 0, b"DST2");
        assert_ne!(a, b);
    }

    #[test]
    fn try_and_increment_valid_point() {
        let dst = b"BN254G1_XMD:SHA-256_TRYANDINC_";
        let x = hash_to_field(b"hello", 0, dst);
        let point = try_and_increment(x);
        assert!(point.is_some());
        let p = point.unwrap();
        assert!(Bn254::is_valid_g1(p.x, p.y));
    }

    #[test]
    fn try_and_increment_rejects_out_of_range() {
        let result = try_and_increment(Bn254::FQ_MODULUS);
        assert!(result.is_none());
    }

    #[test]
    fn legendre_fq_zero() {
        assert!(!legendre_fq(u256::from(0u8)));
    }

    #[test]
    fn sqrt_fq_squared_inverts() {
        let base = u256::from(42u128) % Bn254::FQ_MODULUS;
        let sq = Bn254::mul_fq(base, base);
        let root = sqrt_fq(sq);
        let check = Bn254::mul_fq(root, root);
        assert_eq!(check, sq);
    }

    #[test]
    fn sqrt_fq_is_canonical() {
        let base = u256::from(99u128) % Bn254::FQ_MODULUS;
        let sq = Bn254::mul_fq(base, base);
        let root = sqrt_fq(sq);
        let alt = Bn254::sub_fq(Bn254::FQ_MODULUS, root);
        assert_eq!(Bn254::mul_fq(alt, alt), sq);
        let is_even = root & u256::from(1u8) == u256::from(0u8);
        let alt_is_even = alt & u256::from(1u8) == u256::from(0u8);
        assert!(is_even != alt_is_even);
    }

    #[test]
    fn hash_to_curve_g1_returns_valid_point() {
        let dst = b"BN254G1_XMD:SHA-256_TRYANDINC_";
        let point = hash_to_curve_g1(b"test message", dst);
        assert!(Bn254::is_valid_g1(point.x, point.y));
    }

    #[test]
    fn hash_to_curve_g1_is_deterministic() {
        let dst = b"BN254G1_XMD:SHA-256_TRYANDINC_";
        let a = hash_to_curve_g1(b"deterministic", dst);
        let b = hash_to_curve_g1(b"deterministic", dst);
        assert_eq!(a, b);
    }

    #[test]
    fn hash_to_curve_g1_different_inputs() {
        let dst = b"BN254G1_XMD:SHA-256_TRYANDINC_";
        let a = hash_to_curve_g1(b"input A", dst);
        let b = hash_to_curve_g1(b"input B", dst);
        assert_ne!(a, b);
    }

    #[test]
    fn hash_to_curve_g1_different_dst() {
        let a = hash_to_curve_g1(b"test", b"DST_A");
        let b = hash_to_curve_g1(b"test", b"DST_B");
        assert_ne!(a, b);
    }

    #[test]
    fn hash_to_curve_g1_empty_msg() {
        let dst = b"BN254G1_XMD:SHA-256_TRYANDINC_";
        let point = hash_to_curve_g1(b"", dst);
        assert!(Bn254::is_valid_g1(point.x, point.y));
    }

    #[test]
    fn hash_to_curve_g1_long_msg() {
        let dst = b"BN254G1_XMD:SHA-256_TRYANDINC_";
        let msg = [0xABu8; 1024];
        let point = hash_to_curve_g1(&msg, dst);
        assert!(Bn254::is_valid_g1(point.x, point.y));
    }

    #[test]
    fn hash_to_curve_g1_subgroup_check() {
        let dst = b"BN254G1_XMD:SHA-256_TRYANDINC_";
        let point = hash_to_curve_g1(b"subgroup check", dst);
        assert!(Bn254::is_valid_g1_subgroup(point.x, point.y));
    }
}
