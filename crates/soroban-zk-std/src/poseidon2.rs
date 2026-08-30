//! Poseidon2 Sponge Construction for BN254 (CAP-0075)
//!
//! Wraps `env.crypto_hazmat().poseidon2_permutation()` to provide a high-level
//! absorb/squeeze API without guest-side permutation overhead.
//!
//! Parameters (BN254, t=3): d=5, rounds_f=8, rounds_p=56, rate=2, capacity=1.

use ethnum::u256 as eth_u256;
use soroban_sdk::{symbol_short, vec, Bytes, Env, Vec, U256};
use soroban_zk_core::{Fr, SafeFrom, ZkError};

// ── Sponge geometry ───────────────────────────────────────────────────────────

const T: u32 = 3;
const D: u32 = 5;
const ROUNDS_F: u32 = 8;
const ROUNDS_P: u32 = 56;
const RATE: u32 = 2;

// ── BN254 Fr modulus (used for field-addition during absorption) ───────────────
// r = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001

pub(crate) fn fr_modulus(env: &Env) -> U256 {
    u(
        env,
        0x30644e72e131a029b85045b68181585d,
        0x2833e84879b9709143e1f593f0000001,
    )
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Build a U256 from two 128-bit halves (big-endian).
fn u(env: &Env, hi: u128, lo: u128) -> U256 {
    let mut b = [0u8; 32];
    b[..16].copy_from_slice(&hi.to_be_bytes());
    b[16..].copy_from_slice(&lo.to_be_bytes());
    U256::from_be_bytes(env, &Bytes::from_array(env, &b))
}

/// Field addition mod r: (a + b) mod r.
/// Both inputs are fully reduced modulo the field modulus. The modulus is
/// passed in so callers can reuse a cached value instead of rebuilding it on
/// every addition.
/// Reads a `U256` into a big-endian byte array without any host-side
/// arithmetic (no `sub`/`add` calls that could trap on under/overflow).
fn u256_to_be_array(v: &U256) -> [u8; 32] {
    let bytes = v.to_be_bytes();
    let mut out = [0u8; 32];
    for i in 0..32u32 {
        out[i as usize] = bytes.get_unchecked(i);
    }
    out
}

/// Branchless byte select: returns `a` if `mask_true`, else `b`.
#[inline(always)]
fn ct_byte_select(mask_true: bool, a: u8, b: u8) -> u8 {
    let m = 0u8.wrapping_sub(mask_true as u8);
    (a & m) | (b & !m)
}

/// Constant-time `a >= b` over big-endian byte arrays of equal length.
/// Scans every byte regardless of where the arrays first differ.
fn be_ge<const N: usize>(a: &[u8; N], b: &[u8; N]) -> bool {
    let mut lt = false;
    let mut decided = false;
    for i in 0..N {
        let is_lt = a[i] < b[i];
        let is_gt = a[i] > b[i];
        let this_decides = !decided && (is_lt || is_gt);
        lt = lt || (this_decides && is_lt);
        decided = decided || this_decides;
    }
    !lt
}

fn zero_extend32(a: &[u8; 32]) -> [u8; 33] {
    let mut out = [0u8; 33];
    out[1..].copy_from_slice(a);
    out
}

/// 32-byte + 32-byte -> 33-byte big-endian sum. Plain ripple-carry over
/// primitive `u16`s: no SDK calls, so nothing here can trap.
fn be_add32(a: &[u8; 32], b: &[u8; 32]) -> [u8; 33] {
    let mut out = [0u8; 33];
    let mut carry: u16 = 0;
    for i in (0..32).rev() {
        let s = a[i] as u16 + b[i] as u16 + carry;
        out[i + 1] = (s & 0xFF) as u8;
        carry = s >> 8;
    }
    out[0] = carry as u8;
    out
}

/// 33-byte - 33-byte big-endian difference, wrapping (caller selects
/// whether the result is meaningful via `be_ge`). Borrow propagation uses
/// an arithmetic shift instead of an `if`, so it never branches on the
/// operand values.
fn be_sub33(a: &[u8; 33], b: &[u8; 33]) -> [u8; 33] {
    let mut out = [0u8; 33];
    let mut borrow: i16 = 0;
    for i in (0..33).rev() {
        let d: i16 = a[i] as i16 - b[i] as i16 - borrow;
        borrow = (d >> 15) & 1;
        out[i] = (d & 0xFF) as u8;
    }
    out
}

/// Reduces `x` mod `m` by at most one subtraction, without ever calling a
/// host `sub` that could underflow: the subtraction always runs on plain
/// bytes, and the result is chosen via a branchless mask (Issue #372).
fn reduce_once(x: &[u8; 32], m: &[u8; 32]) -> [u8; 32] {
    let x33 = zero_extend32(x);
    let m33 = zero_extend32(m);
    let ge = be_ge(&x33, &m33);
    let sub = be_sub33(&x33, &m33);
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = ct_byte_select(ge, sub[i + 1], x[i]);
    }
    out
}

/// Constant-time modular addition. Never calls `U256::sub`/`>=` on raw
/// operands (both can trap or branch on secret magnitude via the host);
/// instead reduces both operands and the final sum using masked byte
/// selection over raw arrays (Issue #372).
fn field_add(a: &U256, b: &U256, modulus: &U256) -> U256 {
    let env = a.env();
    let m_arr = u256_to_be_array(modulus);

    // Fully reduce both operands. Each round subtracts the modulus at most
    // once (masked, no branch); the fixed iteration count is constant-time.
    // `r > 2^253`, so any `u256` value needs at most 7 subtractions to reach
    // the canonical range `[0, r)`; 8 rounds give margin for all inputs.
    let mut a_r = u256_to_be_array(a);
    let mut b_r = u256_to_be_array(b);
    for _ in 0..8 {
        a_r = reduce_once(&a_r, &m_arr);
        b_r = reduce_once(&b_r, &m_arr);
    }

    let sum33 = be_add32(&a_r, &b_r);
    let m33 = zero_extend32(&m_arr);
    let ge = be_ge(&sum33, &m33);
    let sub33 = be_sub33(&sum33, &m33);

    let mut result = [0u8; 32];
    for i in 0..32 {
        result[i] = ct_byte_select(ge, sub33[i + 1], sum33[i + 1]);
    }

    let bytes = Bytes::from_array(env, &result);
    U256::from_be_bytes(env, &bytes)
}

fn fr_to_u256(env: &Env, input: Fr) -> U256 {
    let bytes = input.inner().to_be_bytes();
    let bytes = Bytes::from_array(env, &bytes);
    U256::from_be_bytes(env, &bytes)
}

fn u256_to_fr(challenge: U256) -> Result<Fr, ZkError> {
    let mut bytes = [0u8; 32];
    challenge.to_be_bytes().copy_into_slice(&mut bytes);
    Fr::safe_from(eth_u256::from_be_bytes(bytes))
}

// ── BN254 t=3 Poseidon2 constants ─────────────────────────────────────────────

/// Internal matrix diagonal (M_I − I) for t=3 BN254: [1, 1, 2].
pub(crate) fn mat_diag(env: &Env) -> Vec<U256> {
    vec![
        env,
        U256::from_u128(env, 1),
        U256::from_u128(env, 1),
        U256::from_u128(env, 2),
    ]
}

/// 64 round-constant rows (4 full + 56 partial + 4 full) for BN254 Poseidon2 t=3.
/// Source: soroban-env-host-25.0.1 / poseidon2_instance_bn254.rs (RC3).
pub(crate) fn round_constants(env: &Env) -> Vec<Vec<U256>> {
    let z = U256::from_u128(env, 0);

    // 3-element full-round row
    let r3 = |a: U256, b: U256, c: U256| -> Vec<U256> { vec![env, a, b, c] };
    // Partial-round row: only index-0 non-zero
    let r1 = |a: U256| -> Vec<U256> { vec![env, a, z.clone(), z.clone()] };

    let mut rc: Vec<Vec<U256>> = Vec::new(env);

    // ── 4 beginning full rounds ───────────────────────────────────────────
    rc.push_back(r3(
        u(
            env,
            0x1d066a255517b7fd8bddd3a93f7804ef,
            0x7f8fcde48bb4c37a59a09a1a97052816,
        ),
        u(
            env,
            0x29daefb55f6f2dc6ac3f089cebcc6120,
            0xb7c6fef31367b68eb7238547d32c1610,
        ),
        u(
            env,
            0x1f2cb1624a78ee001ecbd88ad959d701,
            0x2572d76f08ec5c4f9e8b7ad7b0b4e1d1,
        ),
    ));
    rc.push_back(r3(
        u(
            env,
            0x0aad2e79f15735f2bd77c0ed3d14aa27,
            0xb11f092a53bbc6e1db0672ded84f31e5,
        ),
        u(
            env,
            0x2252624f8617738cd6f661dd4094375f,
            0x37028a98f1dece66091ccf1595b43f28,
        ),
        u(
            env,
            0x1a24913a928b38485a65a84a291da1ff,
            0x91c20626524b2b87d49f4f2c9018d735,
        ),
    ));
    rc.push_back(r3(
        u(
            env,
            0x22fc468f1759b74d7bfc427b5f11ebb1,
            0x0a41515ddff497b14fd6dae1508fc47a,
        ),
        u(
            env,
            0x1059ca787f1f89ed9cd026e9c9ca107a,
            0xe61956ff0b4121d5efd65515617f6e4d,
        ),
        u(
            env,
            0x02be9473358461d8f61f3536d877de98,
            0x2123011f0bf6f155a45cbbfae8b981ce,
        ),
    ));
    rc.push_back(r3(
        u(
            env,
            0x0ec96c8e32962d462778a749c82ed623,
            0xaba9b669ac5b8736a1ff3a441a5084a4,
        ),
        u(
            env,
            0x292f906e073677405442d9553c45fa3f,
            0x5a47a7cdb8c99f9648fb2e4d814df57e,
        ),
        u(
            env,
            0x274982444157b86726c11b9a0f5e39a5,
            0xcc611160a394ea460c63f0b2ffe5657e,
        ),
    ));

    // ── 56 partial rounds (only index-0 non-zero) ─────────────────────────
    rc.push_back(r1(u(
        env,
        0x1a1d063e54b1e764b63e1855bff015b8,
        0xcedd192f47308731499573f23597d4b5,
    )));
    rc.push_back(r1(u(
        env,
        0x26abc66f3fdf8e68839d109562590637,
        0x08235dccc1aa3793b91b002c5b257c37,
    )));
    rc.push_back(r1(u(
        env,
        0x0c7c64a9d887385381a578cfed5aed37,
        0x0754427aabca92a70b3c2b12ff4d7be8,
    )));
    rc.push_back(r1(u(
        env,
        0x1cf5998769e9fab79e17f0b6d08b2d1e,
        0xba2ebac30dc386b0edd383831354b495,
    )));
    rc.push_back(r1(u(
        env,
        0x0f5e3a8566be31b7564ca60461e9e08b,
        0x19828764a9669bc17aba0b97e66b0109,
    )));
    rc.push_back(r1(u(
        env,
        0x18df6a9d19ea90d895e60e4db0794a01,
        0xf359a53a180b7d4b42bf3d7a531c976e,
    )));
    rc.push_back(r1(u(
        env,
        0x04f7bf2c5c0538ac6e4b782c3c6e601a,
        0xd0ea1d3a3b9d25ef4e324055fa3123dc,
    )));
    rc.push_back(r1(u(
        env,
        0x29c76ce22255206e3c40058523748531,
        0xe770c0584aa2328ce55d54628b89ebe6,
    )));
    rc.push_back(r1(u(
        env,
        0x198d425a45b78e85c053659ab4347f5d,
        0x65b1b8e9c6108dbe00e0e945dbc5ff15,
    )));
    rc.push_back(r1(u(
        env,
        0x25ee27ab6296cd5e6af3cc79c598a1da,
        0xa7ff7f6878b3c49d49d3a9a90c3fdf74,
    )));
    rc.push_back(r1(u(
        env,
        0x138ea8e0af41a1e024561001c0b6eb15,
        0x05845d7d0c55b1b2c0f88687a96d1381,
    )));
    rc.push_back(r1(u(
        env,
        0x306197fb3fab671ef6e7c2cba2eefd0e,
        0x42851b5b9811f2ca4013370a01d95687,
    )));
    rc.push_back(r1(u(
        env,
        0x1a0c7d52dc32a4432b66f0b4894d4f1a,
        0x21db7565e5b4250486419eaf00e8f620,
    )));
    rc.push_back(r1(u(
        env,
        0x2b46b418de80915f3ff86a8e5c8bdfcc,
        0xebfbe5f55163cd6caa52997da2c54a9f,
    )));
    rc.push_back(r1(u(
        env,
        0x12d3e0dc0085873701f8b777b9673af9,
        0x613a1af5db48e05bfb46e312b5829f64,
    )));
    rc.push_back(r1(u(
        env,
        0x263390cf74dc3a8870f5002ed21d089f,
        0xfb2bf768230f648dba338a5cb19b3a1f,
    )));
    rc.push_back(r1(u(
        env,
        0x0a14f33a5fe668a60ac884b4ca607ad0,
        0xf8abb5af40f96f1d7d543db52b003dcd,
    )));
    rc.push_back(r1(u(
        env,
        0x28ead9c586513eab1a5e86509d68b2da,
        0x27be3a4f01171a1dd847df829bc683b9,
    )));
    rc.push_back(r1(u(
        env,
        0x1c6ab1c328c3c6430972031f1bdb2ac9,
        0x888f0ea1abe71cffea16cda6e1a7416c,
    )));
    rc.push_back(r1(u(
        env,
        0x1fc7e71bc0b819792b2500239f7f8de0,
        0x4f6decd608cb98a932346015c5b42c94,
    )));
    rc.push_back(r1(u(
        env,
        0x03e107eb3a42b2ece380e0d860298f17,
        0xc0c1e197c952650ee6dd85b93a0ddaa8,
    )));
    rc.push_back(r1(u(
        env,
        0x2d354a251f381a4669c0d52bf88b772c,
        0x46452ca57c08697f454505f6941d78cd,
    )));
    rc.push_back(r1(u(
        env,
        0x094af88ab05d94baf687ef14bc566d1c,
        0x522551d61606eda3d14b4606826f794b,
    )));
    rc.push_back(r1(u(
        env,
        0x19705b783bf3d2dc19bcaeabf02f8ca5,
        0xe1ab5b6f2e3195a9d52b2d249d1396f7,
    )));
    rc.push_back(r1(u(
        env,
        0x09bf4acc3a8bce3f1fcc33fee54fc5b2,
        0x8723b16b7d740a3e60cef6852271200e,
    )));
    rc.push_back(r1(u(
        env,
        0x1803f8200db6013c50f83c0c8fab6284,
        0x3413732f301f7058543a073f3f3b5e4e,
    )));
    rc.push_back(r1(u(
        env,
        0x0f80afb5046244de30595b160b8d1f38,
        0xbf6fb02d4454c0add41f7fef2faf3e5c,
    )));
    rc.push_back(r1(u(
        env,
        0x126ee1f8504f15c3d77f0088c1cfc964,
        0xabcfcf643f4a6fea7dc3f98219529d78,
    )));
    rc.push_back(r1(u(
        env,
        0x23c203d10cfcc60f69bfb3d919552ca1,
        0x0ffb4ee63175ddf8ef86f991d7d0a591,
    )));
    rc.push_back(r1(u(
        env,
        0x2a2ae15d8b143709ec0d09705fa3a630,
        0x3dec1ee4eec2cf747c5a339f7744fb94,
    )));
    rc.push_back(r1(u(
        env,
        0x07b60dee586ed6ef47e5c381ab6343ec,
        0xc3d3b3006cb461bbb6b5d89081970b2b,
    )));
    rc.push_back(r1(u(
        env,
        0x27316b559be3edfd885d95c494c1ae3d,
        0x8a98a320baa7d152132cfe583c9311bd,
    )));
    rc.push_back(r1(u(
        env,
        0x1d5c49ba157c32b8d8937cb2d3f84311,
        0xef834cc2a743ed662f5f9af0c0342e76,
    )));
    rc.push_back(r1(u(
        env,
        0x2f8b124e78163b2f332774e0b850b5ec,
        0x09c01bf6979938f67c24bd5940968488,
    )));
    rc.push_back(r1(u(
        env,
        0x1e6843a5457416b6dc5b7aa09a9ce21b,
        0x1d4cba6554e51d84665f75260113b3d5,
    )));
    rc.push_back(r1(u(
        env,
        0x11cdf00a35f650c55fca25c9929c8ad9,
        0xa68daf9ac6a189ab1f5bc79f21641d4b,
    )));
    rc.push_back(r1(u(
        env,
        0x21632de3d3bbc5e42ef36e588158d6d4,
        0x608b2815c77355b7e82b5b9b7eb560bc,
    )));
    rc.push_back(r1(u(
        env,
        0x0de625758452efbd97b27025fbd245e0,
        0x255ae48ef2a329e449d7b5c51c18498a,
    )));
    rc.push_back(r1(u(
        env,
        0x2ad253c053e75213e2febfd4d976cc01,
        0xdd9e1e1c6f0fb6b09b09546ba0838098,
    )));
    rc.push_back(r1(u(
        env,
        0x1d6b169ed63872dc6ec7681ec39b3be9,
        0x3dd49cdd13c813b7d35702e38d60b077,
    )));
    rc.push_back(r1(u(
        env,
        0x1660b740a143664bb9127c4941b67fed,
        0x0be3ea70a24d5568c3a54e706cfef7fe,
    )));
    rc.push_back(r1(u(
        env,
        0x0065a92d1de81f34114f4ca2deef76e0,
        0xceacdddb12cf879096a29f10376ccbfe,
    )));
    rc.push_back(r1(u(
        env,
        0x1f11f065202535987367f823da7d672c,
        0x353ebe2ccbc4869bcf30d50a5871040d,
    )));
    rc.push_back(r1(u(
        env,
        0x26596f5c5dd5a5d1b437ce7b14a2c3dd,
        0x3bd1d1a39b6759ba110852d17df0693e,
    )));
    rc.push_back(r1(u(
        env,
        0x16f49bc727e45a2f7bf3056efcf8b6d3,
        0x8539c4163a5f1e706743db15af91860f,
    )));
    rc.push_back(r1(u(
        env,
        0x1abe1deb45b3e3119954175efb331bf4,
        0x568feaf7ea8b3dc5e1a4e7438dd39e5f,
    )));
    rc.push_back(r1(u(
        env,
        0x0e426ccab66984d1d8993a74ca548b77,
        0x9f5db92aaec5f102020d34aea15fba59,
    )));
    rc.push_back(r1(u(
        env,
        0x0e7c30c2e2e8957f4933bd1942053f1f,
        0x0071684b902d534fa841924303f6a6c6,
    )));
    rc.push_back(r1(u(
        env,
        0x0812a017ca92cf0a1622708fc7edff1d,
        0x6166ded6e3528ead4c76e1f31d3fc69d,
    )));
    rc.push_back(r1(u(
        env,
        0x21a5ade3df2bc1b5bba949d1db960400,
        0x68afe5026edd7a9c2e276b47cf010d54,
    )));
    rc.push_back(r1(u(
        env,
        0x01f3035463816c84ad711bf1a058c6c6,
        0xbd101945f50e5afe72b1a5233f8749ce,
    )));
    rc.push_back(r1(u(
        env,
        0x0b115572f038c0e2028c2aafc2d06a5e,
        0x8bf2f9398dbd0fdf4dcaa82b0f0c1c8b,
    )));
    rc.push_back(r1(u(
        env,
        0x1c38ec0b99b62fd4f0ef255543f50d2e,
        0x27fc24db42bc910a3460613b6ef59e2f,
    )));
    rc.push_back(r1(u(
        env,
        0x1c89c6d9666272e8425c3ff1f4ac737b,
        0x2f5d314606a297d4b1d0b254d880c53e,
    )));
    rc.push_back(r1(u(
        env,
        0x03326e643580356bf6d44008ae4c042a,
        0x21ad4880097a5eb38b71e2311bb88f8f,
    )));
    rc.push_back(r1(u(
        env,
        0x268076b0054fb73f67cee9ea0e51e3ad,
        0x50f27a6434b5dceb5bdde2299910a4c9,
    )));

    // ── 4 ending full rounds ──────────────────────────────────────────────
    rc.push_back(r3(
        u(
            env,
            0x1acd63c67fbc9ab1626ed93491bda32e,
            0x5da18ea9d8e4f10178d04aa6f8747ad0,
        ),
        u(
            env,
            0x19f8a5d670e8ab66c4e3144be58ef690,
            0x1bf93375e2323ec3ca8c86cd2a28b5a5,
        ),
        u(
            env,
            0x1c0dc443519ad7a86efa40d2df10a011,
            0x068193ea51f6c92ae1cfbb5f7b9b6893,
        ),
    ));
    rc.push_back(r3(
        u(
            env,
            0x14b39e7aa4068dbe50fe7190e421dc19,
            0xfbeab33cb4f6a2c4180e4c3224987d3d,
        ),
        u(
            env,
            0x1d449b71bd826ec58f28c63ea6c561b7,
            0xb820fc519f01f021afb1e35e28b0795e,
        ),
        u(
            env,
            0x1ea2c9a89baaddbb60fa97fe60fe9d8e,
            0x89de141689d1252276524dc0a9e987fc,
        ),
    ));
    rc.push_back(r3(
        u(
            env,
            0x0478d66d43535a8cb57e9c1c3d6a2bd7,
            0x591f9a46a0e9c058134d5cefdb3c7ff1,
        ),
        u(
            env,
            0x19272db71eece6a6f608f3b2717f9cd2,
            0x662e26ad86c400b21cde5e4a7b00bebe,
        ),
        u(
            env,
            0x14226537335cab33c749c746f09208ab,
            0xb2dd1bd66a87ef75039be846af134166,
        ),
    ));
    rc.push_back(r3(
        u(
            env,
            0x01fd6af15956294f9dfe38c0d976a088,
            0xb21c21e4a1c2e823f912f44961f9a9ce,
        ),
        u(
            env,
            0x18e5abedd626ec307bca190b8b2cab1a,
            0xaee2e62ed229ba5a5ad8518d4e5f2a57,
        ),
        u(
            env,
            0x0fc1bbceba0590f5abbdffa6d3b35e32,
            0x97c021a3a409926d0e2d54dc1c84fda6,
        ),
    ));

    rc
}

// ── Sponge ────────────────────────────────────────────────────────────────────

/// Poseidon2 sponge over BN254 Fr (t=3, rate=2, capacity=1).
///
/// Directly calls `env.crypto_hazmat().poseidon2_permutation()` so the
/// permutation runs as a single host call — no guest-side loop overhead.
///
/// # Example
/// ```ignore
/// let mut sponge = Poseidon2Sponge::new(&env);
/// sponge.absorb(&inputs);
/// let digest = sponge.squeeze();
/// ```
pub struct Poseidon2Sponge {
    env: Env,
    state: Vec<U256>,
    /// Next rate slot to write into during absorption.
    rate_idx: u32,
    /// Internal matrix diagonal, materialised once per sponge instead of on
    /// every permutation.
    mat: Vec<U256>,
    /// 64 round-constant rows, materialised once per sponge.
    rc: Vec<Vec<U256>>,
    /// BN254 Fr modulus, reused across all field additions.
    modulus: U256,
}

impl Poseidon2Sponge {
    /// Create a new sponge with zeroed state, building the BN254 constants
    /// from code (no contract storage required).
    ///
    /// The round constants and matrix diagonal are computed once here and
    /// reused across every [`Poseidon2Sponge::absorb`]/[`Poseidon2Sponge::squeeze`]
    /// permutation, rather than being rebuilt on each permutation.
    pub fn new(env: &Env) -> Self {
        Self::with_constants(env, mat_diag(env), round_constants(env), fr_modulus(env))
    }

    /// Create a new sponge whose BN254 constants are sourced from the contract
    /// instance storage cache (Issue #124).
    ///
    /// On the first invocation within a contract the constants are computed and
    /// written to `StorageType::Instance`; subsequent invocations read them back
    /// from storage instead of rebuilding them. Must be called from within a
    /// contract invocation context (it touches instance storage).
    pub fn new_cached(env: &Env) -> Self {
        Self::with_constants(
            env,
            crate::cache::mat_diag(env),
            crate::cache::round_constants(env),
            crate::cache::fr_modulus(env),
        )
    }

    /// Shared constructor: build a zeroed sponge around the supplied constants.
    fn with_constants(env: &Env, mat: Vec<U256>, rc: Vec<Vec<U256>>, modulus: U256) -> Self {
        let z = U256::from_u128(env, 0);
        let state = vec![env, z.clone(), z.clone(), z];
        Self {
            env: env.clone(),
            state,
            rate_idx: 0,
            mat,
            rc,
            modulus,
        }
    }

    /// Absorb a slice of BN254 Fr field elements into the sponge.
    pub fn absorb(&mut self, inputs: &[U256]) {
        for input in inputs {
            let cur = self.state.get(self.rate_idx).unwrap();
            let next = field_add(&cur, input, &self.modulus);
            self.state.set(self.rate_idx, next);
            self.rate_idx += 1;
            if self.rate_idx == RATE {
                self.permute();
                self.rate_idx = 0;
            }
        }
    }

    /// Squeeze one field element.
    ///
    /// Pads and applies the permutation if any unprocessed input remains,
    /// then returns the first element of the rate portion.
    pub fn squeeze(&mut self) -> U256 {
        // Flush any buffered input with a final permutation.
        self.permute();
        self.rate_idx = 0;
        self.state.get(0).unwrap()
    }

    fn permute(&mut self) {
        let field = symbol_short!("BN254");
        self.state = self.env.crypto_hazmat().poseidon2_permutation(
            &self.state,
            field,
            T,
            D,
            ROUNDS_F,
            ROUNDS_P,
            &self.mat,
            &self.rc,
        );
    }
}

// ── hash_to_field ─────────────────────────────────────────────────────────────

/// Hash a slice of BN254 Fr field elements to a single field element.
///
/// Compatible with Noir/Circom Poseidon2 constraints (t=3, d=5, rate=2).
/// Uses capacity-zero sponge initialisation.
pub fn hash_to_field(env: &Env, inputs: &[U256]) -> U256 {
    let mut sponge = Poseidon2Sponge::new(env);
    sponge.absorb(inputs);
    sponge.squeeze()
}

/// Instance-cached variant of [`hash_to_field`] (Issue #124).
///
/// Identical output to [`hash_to_field`], but the BN254 round constants and
/// matrix diagonal are loaded from (and lazily populated into) the contract
/// instance storage cache rather than rebuilt from code. Must be called from
/// within a contract invocation context.
pub fn hash_to_field_cached(env: &Env, inputs: &[U256]) -> U256 {
    let mut sponge = Poseidon2Sponge::new_cached(env);
    sponge.absorb(inputs);
    sponge.squeeze()
}

/// Fiat-Shamir transcript built on top of the BN254 Poseidon2 sponge.
///
/// The transcript is stateful: each absorb updates the sponge state, and each
/// squeeze advances the permutation before producing the next challenge.
pub struct Transcript {
    env: Env,
    sponge: Poseidon2Sponge,
}

impl Transcript {
    /// Create a fresh transcript with an empty Poseidon2 state.
    pub fn new(env: &Env) -> Self {
        Self {
            env: env.clone(),
            sponge: Poseidon2Sponge::new(env),
        }
    }

    /// Absorb canonical BN254 field elements into the transcript.
    pub fn absorb(&mut self, inputs: &[Fr]) {
        for input in inputs {
            let raw = fr_to_u256(&self.env, *input);
            self.sponge.absorb(core::slice::from_ref(&raw));
        }
    }

    /// Squeeze the next Fiat-Shamir challenge as a validated BN254 `Fr`.
    pub fn squeeze_challenge(&mut self) -> Result<Fr, ZkError> {
        u256_to_fr(self.sponge.squeeze())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ethnum::u256;
    use soroban_sdk::Env;

    fn env() -> Env {
        let e = Env::default();
        e.cost_estimate().budget().reset_unlimited();
        e
    }

    #[test]
    fn known_answer_permutation_of_0_1_2() {
        // Verified against soroban-env-host-25.0.1 test vector:
        // poseidon2_permutation([0, 1, 2]) over BN254 Fr
        let env = env();
        let field = symbol_short!("BN254");
        let state = vec![
            &env,
            U256::from_u128(&env, 0),
            U256::from_u128(&env, 1),
            U256::from_u128(&env, 2),
        ];
        let mat = mat_diag(&env);
        let rc = round_constants(&env);
        let out = env
            .crypto_hazmat()
            .poseidon2_permutation(&state, field, T, D, ROUNDS_F, ROUNDS_P, &mat, &rc);

        assert_eq!(
            out.get(0).unwrap(),
            u(
                &env,
                0x0bb61d24daca55eebcb1929a82650f32,
                0x8134334da98ea4f847f760054f4a3033
            )
        );
        assert_eq!(
            out.get(1).unwrap(),
            u(
                &env,
                0x303b6f7c86d043bfcbcc80214f26a302,
                0x77a15d3f74ca654992defe7ff8d03570
            )
        );
        assert_eq!(
            out.get(2).unwrap(),
            u(
                &env,
                0x1ed25194542b12eef8617361c3ba7c52,
                0xe660b145994427cc86296242cf766ec8
            )
        );
    }

    #[test]
    fn field_add_reduces_when_sum_exceeds_modulus() {
        let env = env();
        let modulus = fr_modulus(&env);
        let a = modulus.clone().sub(&U256::from_u128(&env, 1));
        let b = U256::from_u128(&env, 2);

        let result = field_add(&a, &b, &modulus);

        assert_eq!(result, U256::from_u128(&env, 1));
    }

    #[test]
    fn field_add_no_panic_on_max_boundary_values() {
        let env = env();
        let modulus = fr_modulus(&env);

        // Deliberately near the 2^256 boundary: a = U256::MAX - 1,
        // b = U256::MAX - 2. Their naive sum exceeds 2^256, which previously
        // panicked the host via a direct `.add()`.
        let max = U256::from_be_bytes(&env, &Bytes::from_array(&env, &[0xffu8; 32]));
        let a = max.sub(&U256::from_u128(&env, 1));
        let b = max.sub(&U256::from_u128(&env, 2));

        // Must not panic and must return a properly reduced field element.
        let result = field_add(&a, &b, &modulus);

        // Cross-check the expected value in ethnum space (reduce each operand
        // first so the addition is in-range, exactly as field_add does).
        let mut mb = [0u8; 32];
        modulus.to_be_bytes().copy_into_slice(&mut mb);
        let mv = eth_u256::from_be_bytes(mb);
        let max_eth = eth_u256::from_be_bytes([0xffu8; 32]);
        let av = (max_eth - eth_u256::from(1u8)) % mv;
        let bv = (max_eth - eth_u256::from(2u8)) % mv;
        let expected_eth = av + bv;
        let expected_eth = if expected_eth >= mv {
            expected_eth - mv
        } else {
            expected_eth
        };
        let expected =
            U256::from_be_bytes(&env, &Bytes::from_array(&env, &expected_eth.to_be_bytes()));

        assert_eq!(result, expected);
        assert!(result < modulus);
    }

    #[test]
    fn hash_to_field_is_deterministic() {
        let env = env();
        let inputs = [U256::from_u128(&env, 1), U256::from_u128(&env, 2)];
        let a = hash_to_field(&env, &inputs);
        let b = hash_to_field(&env, &inputs);
        assert_eq!(a, b);
    }

    #[test]
    fn different_inputs_give_different_outputs() {
        let env = env();
        let a = hash_to_field(&env, &[U256::from_u128(&env, 1)]);
        let b = hash_to_field(&env, &[U256::from_u128(&env, 2)]);
        assert_ne!(a, b);
    }

    #[test]
    fn hash_empty_input_does_not_panic() {
        let env = env();
        let out = hash_to_field(&env, &[]);
        assert_ne!(out, U256::from_u128(&env, 0));
    }

    #[test]
    fn hash_single_element() {
        let env = env();
        let out = hash_to_field(&env, &[U256::from_u128(&env, 42)]);
        assert_ne!(out, U256::from_u128(&env, 0));
    }

    #[test]
    fn absorb_three_elements_triggers_two_permutations() {
        // 3 inputs: absorb fills rate=2 (permute), then 1 left → permute on squeeze
        let env = env();
        let inputs = [
            U256::from_u128(&env, 1),
            U256::from_u128(&env, 2),
            U256::from_u128(&env, 3),
        ];
        let out = hash_to_field(&env, &inputs);
        assert_ne!(out, U256::from_u128(&env, 0));
    }

    #[test]
    fn absorb_four_elements_fills_two_blocks() {
        let env = env();
        let inputs = [
            U256::from_u128(&env, 10),
            U256::from_u128(&env, 20),
            U256::from_u128(&env, 30),
            U256::from_u128(&env, 40),
        ];
        let out = hash_to_field(&env, &inputs);
        assert_ne!(out, U256::from_u128(&env, 0));
    }

    #[test]
    fn order_matters() {
        let env = env();
        let a = hash_to_field(&env, &[U256::from_u128(&env, 1), U256::from_u128(&env, 2)]);
        let b = hash_to_field(&env, &[U256::from_u128(&env, 2), U256::from_u128(&env, 1)]);
        assert_ne!(a, b);
    }

    fn fr(value: u128) -> Fr {
        Fr::safe_from(u256::from(value)).unwrap()
    }

    #[test]
    fn transcript_is_deterministic() {
        let env = env();
        let inputs = [fr(1), fr(2), fr(3)];

        let mut left = Transcript::new(&env);
        left.absorb(&inputs);
        let left_challenge = left.squeeze_challenge().unwrap();

        let mut right = Transcript::new(&env);
        right.absorb(&inputs);
        let right_challenge = right.squeeze_challenge().unwrap();

        assert_eq!(left_challenge, right_challenge);
    }

    #[test]
    fn transcript_order_matters() {
        let env = env();
        let a = [fr(1), fr(2)];
        let b = [fr(2), fr(1)];

        let mut left = Transcript::new(&env);
        left.absorb(&a);
        let left_challenge = left.squeeze_challenge().unwrap();

        let mut right = Transcript::new(&env);
        right.absorb(&b);
        let right_challenge = right.squeeze_challenge().unwrap();

        assert_ne!(left_challenge, right_challenge);
    }

    #[test]
    fn transcript_squeezes_progress_state() {
        let env = env();
        let mut transcript = Transcript::new(&env);
        transcript.absorb(&[fr(42)]);

        let first = transcript.squeeze_challenge().unwrap();
        let second = transcript.squeeze_challenge().unwrap();

        assert_ne!(first, second);
    }
}
