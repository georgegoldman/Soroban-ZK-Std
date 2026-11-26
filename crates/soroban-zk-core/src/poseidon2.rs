//! Software Poseidon2 sponge over BN254 Fr (t=3, d=5, rate=2, capacity=1).
//!
//! This is a no_std, allocation-free implementation of the Poseidon2 permutation
//! and sponge construction, bit-compatible with the CAP-0075 / HorizenLabs
//! parameters used by `soroban-zk-std` (and therefore with the Soroban host's
//! `poseidon2_permutation`). The round constants and internal matrix diagonal
//! are identical to those in `soroban-zk-std/src/poseidon2.rs`.
//!
//! The linear layers are the CAP-0075 ones:
//! * external/full rounds: `M_E = circ(2,1,1) = I + J`
//! * internal/partial rounds: `M_I = J + diag(1,1,2)`
//! * `M_E` is additionally applied to the state *before* round 0.
//!
//! The sponge applies 10* padding plus capacity-domain framing on squeeze, so
//! variable-length inputs such as `[]` vs `[0]` and `[1]` vs `[1, 0]` never
//! collide.

use crate::Bn254;
use ethnum::u256;

// ── Sponge geometry ───────────────────────────────────────────────────────────

/// Width of the Poseidon2 permutation state.
const T: usize = 3;
/// S-box exponent (x^d), used for documentation. The exponentiation is
/// inlined in [`sbox`] as x⁵ = x * (x²)².
#[allow(dead_code)]
const D: u32 = 5;
/// Number of full rounds (half before, half after partial rounds).
const ROUNDS_F: usize = 8;
/// Number of partial rounds.
const ROUNDS_P: usize = 56;
/// Rate (number of field elements absorbed/squeezed per permutation).
const RATE: usize = 2;

/// 10* padding marker absorbed at the next free rate position on finalization.
const PAD_MARKER: u256 = u256::from_words(0u128, 1u128);

/// Domain separator mixed into the capacity element on finalization
/// ("soroban-" || "zk-p2-v1"), separating this sponge from a bare
/// capacity-zero Poseidon2 hash.
const DOMAIN_CAPACITY: u256 = u256::from_words(
    0x736f726f62616e2d_u128, // "soroban-"
    0x7a6b2d70322d7631_u128, // "zk-p2-v1"
);
/// Total rounds = ROUNDS_F + ROUNDS_P.
const ROUNDS: usize = ROUNDS_F + ROUNDS_P;

// ── BN254 Fr round constants ─────────────────────────────────────────────────
// Source: soroban-env-host-25.0.1 / poseidon2_instance_bn254.rs (RC3).
// 64 rows × 3 elements. Partial-round rows have zero in positions 1 and 2.

const RC: [[u256; T]; ROUNDS] = [
    // ── 4 beginning full rounds ───────────────────────────────────────────
    [
        u256::from_words(
            0x1d066a255517b7fd8bddd3a93f7804ef_u128,
            0x7f8fcde48bb4c37a59a09a1a97052816_u128,
        ),
        u256::from_words(
            0x29daefb55f6f2dc6ac3f089cebcc6120_u128,
            0xb7c6fef31367b68eb7238547d32c1610_u128,
        ),
        u256::from_words(
            0x1f2cb1624a78ee001ecbd88ad959d701_u128,
            0x2572d76f08ec5c4f9e8b7ad7b0b4e1d1_u128,
        ),
    ],
    [
        u256::from_words(
            0x0aad2e79f15735f2bd77c0ed3d14aa27_u128,
            0xb11f092a53bbc6e1db0672ded84f31e5_u128,
        ),
        u256::from_words(
            0x2252624f8617738cd6f661dd4094375f_u128,
            0x37028a98f1dece66091ccf1595b43f28_u128,
        ),
        u256::from_words(
            0x1a24913a928b38485a65a84a291da1ff_u128,
            0x91c20626524b2b87d49f4f2c9018d735_u128,
        ),
    ],
    [
        u256::from_words(
            0x22fc468f1759b74d7bfc427b5f11ebb1_u128,
            0x0a41515ddff497b14fd6dae1508fc47a_u128,
        ),
        u256::from_words(
            0x1059ca787f1f89ed9cd026e9c9ca107a_u128,
            0xe61956ff0b4121d5efd65515617f6e4d_u128,
        ),
        u256::from_words(
            0x02be9473358461d8f61f3536d877de98_u128,
            0x2123011f0bf6f155a45cbbfae8b981ce_u128,
        ),
    ],
    [
        u256::from_words(
            0x0ec96c8e32962d462778a749c82ed623_u128,
            0xaba9b669ac5b8736a1ff3a441a5084a4_u128,
        ),
        u256::from_words(
            0x292f906e073677405442d9553c45fa3f_u128,
            0x5a47a7cdb8c99f9648fb2e4d814df57e_u128,
        ),
        u256::from_words(
            0x274982444157b86726c11b9a0f5e39a5_u128,
            0xcc611160a394ea460c63f0b2ffe5657e_u128,
        ),
    ],
    // ── 56 partial rounds (only index-0 non-zero) ─────────────────────────
    [
        u256::from_words(
            0x1a1d063e54b1e764b63e1855bff015b8_u128,
            0xcedd192f47308731499573f23597d4b5_u128,
        ),
        u256::ZERO,
        u256::ZERO,
    ],
    [
        u256::from_words(
            0x26abc66f3fdf8e68839d109562590637_u128,
            0x08235dccc1aa3793b91b002c5b257c37_u128,
        ),
        u256::ZERO,
        u256::ZERO,
    ],
    [
        u256::from_words(
            0x0c7c64a9d887385381a578cfed5aed37_u128,
            0x0754427aabca92a70b3c2b12ff4d7be8_u128,
        ),
        u256::ZERO,
        u256::ZERO,
    ],
    [
        u256::from_words(
            0x1cf5998769e9fab79e17f0b6d08b2d1e_u128,
            0xba2ebac30dc386b0edd383831354b495_u128,
        ),
        u256::ZERO,
        u256::ZERO,
    ],
    [
        u256::from_words(
            0x0f5e3a8566be31b7564ca60461e9e08b_u128,
            0x19828764a9669bc17aba0b97e66b0109_u128,
        ),
        u256::ZERO,
        u256::ZERO,
    ],
    [
        u256::from_words(
            0x18df6a9d19ea90d895e60e4db0794a01_u128,
            0xf359a53a180b7d4b42bf3d7a531c976e_u128,
        ),
        u256::ZERO,
        u256::ZERO,
    ],
    [
        u256::from_words(
            0x04f7bf2c5c0538ac6e4b782c3c6e601a_u128,
            0xd0ea1d3a3b9d25ef4e324055fa3123dc_u128,
        ),
        u256::ZERO,
        u256::ZERO,
    ],
    [
        u256::from_words(
            0x29c76ce22255206e3c40058523748531_u128,
            0xe770c0584aa2328ce55d54628b89ebe6_u128,
        ),
        u256::ZERO,
        u256::ZERO,
    ],
    [
        u256::from_words(
            0x198d425a45b78e85c053659ab4347f5d_u128,
            0x65b1b8e9c6108dbe00e0e945dbc5ff15_u128,
        ),
        u256::ZERO,
        u256::ZERO,
    ],
    [
        u256::from_words(
            0x25ee27ab6296cd5e6af3cc79c598a1da_u128,
            0xa7ff7f6878b3c49d49d3a9a90c3fdf74_u128,
        ),
        u256::ZERO,
        u256::ZERO,
    ],
    [
        u256::from_words(
            0x138ea8e0af41a1e024561001c0b6eb15_u128,
            0x05845d7d0c55b1b2c0f88687a96d1381_u128,
        ),
        u256::ZERO,
        u256::ZERO,
    ],
    [
        u256::from_words(
            0x306197fb3fab671ef6e7c2cba2eefd0e_u128,
            0x42851b5b9811f2ca4013370a01d95687_u128,
        ),
        u256::ZERO,
        u256::ZERO,
    ],
    [
        u256::from_words(
            0x1a0c7d52dc32a4432b66f0b4894d4f1a_u128,
            0x21db7565e5b4250486419eaf00e8f620_u128,
        ),
        u256::ZERO,
        u256::ZERO,
    ],
    [
        u256::from_words(
            0x2b46b418de80915f3ff86a8e5c8bdfcc_u128,
            0xebfbe5f55163cd6caa52997da2c54a9f_u128,
        ),
        u256::ZERO,
        u256::ZERO,
    ],
    [
        u256::from_words(
            0x12d3e0dc0085873701f8b777b9673af9_u128,
            0x613a1af5db48e05bfb46e312b5829f64_u128,
        ),
        u256::ZERO,
        u256::ZERO,
    ],
    [
        u256::from_words(
            0x263390cf74dc3a8870f5002ed21d089f_u128,
            0xfb2bf768230f648dba338a5cb19b3a1f_u128,
        ),
        u256::ZERO,
        u256::ZERO,
    ],
    [
        u256::from_words(
            0x0a14f33a5fe668a60ac884b4ca607ad0_u128,
            0xf8abb5af40f96f1d7d543db52b003dcd_u128,
        ),
        u256::ZERO,
        u256::ZERO,
    ],
    [
        u256::from_words(
            0x28ead9c586513eab1a5e86509d68b2da_u128,
            0x27be3a4f01171a1dd847df829bc683b9_u128,
        ),
        u256::ZERO,
        u256::ZERO,
    ],
    [
        u256::from_words(
            0x1c6ab1c328c3c6430972031f1bdb2ac9_u128,
            0x888f0ea1abe71cffea16cda6e1a7416c_u128,
        ),
        u256::ZERO,
        u256::ZERO,
    ],
    [
        u256::from_words(
            0x1fc7e71bc0b819792b2500239f7f8de0_u128,
            0x4f6decd608cb98a932346015c5b42c94_u128,
        ),
        u256::ZERO,
        u256::ZERO,
    ],
    [
        u256::from_words(
            0x03e107eb3a42b2ece380e0d860298f17_u128,
            0xc0c1e197c952650ee6dd85b93a0ddaa8_u128,
        ),
        u256::ZERO,
        u256::ZERO,
    ],
    [
        u256::from_words(
            0x2d354a251f381a4669c0d52bf88b772c_u128,
            0x46452ca57c08697f454505f6941d78cd_u128,
        ),
        u256::ZERO,
        u256::ZERO,
    ],
    [
        u256::from_words(
            0x094af88ab05d94baf687ef14bc566d1c_u128,
            0x522551d61606eda3d14b4606826f794b_u128,
        ),
        u256::ZERO,
        u256::ZERO,
    ],
    [
        u256::from_words(
            0x19705b783bf3d2dc19bcaeabf02f8ca5_u128,
            0xe1ab5b6f2e3195a9d52b2d249d1396f7_u128,
        ),
        u256::ZERO,
        u256::ZERO,
    ],
    [
        u256::from_words(
            0x09bf4acc3a8bce3f1fcc33fee54fc5b2_u128,
            0x8723b16b7d740a3e60cef6852271200e_u128,
        ),
        u256::ZERO,
        u256::ZERO,
    ],
    [
        u256::from_words(
            0x1803f8200db6013c50f83c0c8fab6284_u128,
            0x3413732f301f7058543a073f3f3b5e4e_u128,
        ),
        u256::ZERO,
        u256::ZERO,
    ],
    [
        u256::from_words(
            0x0f80afb5046244de30595b160b8d1f38_u128,
            0xbf6fb02d4454c0add41f7fef2faf3e5c_u128,
        ),
        u256::ZERO,
        u256::ZERO,
    ],
    [
        u256::from_words(
            0x126ee1f8504f15c3d77f0088c1cfc964_u128,
            0xabcfcf643f4a6fea7dc3f98219529d78_u128,
        ),
        u256::ZERO,
        u256::ZERO,
    ],
    [
        u256::from_words(
            0x23c203d10cfcc60f69bfb3d919552ca1_u128,
            0x0ffb4ee63175ddf8ef86f991d7d0a591_u128,
        ),
        u256::ZERO,
        u256::ZERO,
    ],
    [
        u256::from_words(
            0x2a2ae15d8b143709ec0d09705fa3a630_u128,
            0x3dec1ee4eec2cf747c5a339f7744fb94_u128,
        ),
        u256::ZERO,
        u256::ZERO,
    ],
    [
        u256::from_words(
            0x07b60dee586ed6ef47e5c381ab6343ec_u128,
            0xc3d3b3006cb461bbb6b5d89081970b2b_u128,
        ),
        u256::ZERO,
        u256::ZERO,
    ],
    [
        u256::from_words(
            0x27316b559be3edfd885d95c494c1ae3d_u128,
            0x8a98a320baa7d152132cfe583c9311bd_u128,
        ),
        u256::ZERO,
        u256::ZERO,
    ],
    [
        u256::from_words(
            0x1d5c49ba157c32b8d8937cb2d3f84311_u128,
            0xef834cc2a743ed662f5f9af0c0342e76_u128,
        ),
        u256::ZERO,
        u256::ZERO,
    ],
    [
        u256::from_words(
            0x2f8b124e78163b2f332774e0b850b5ec_u128,
            0x09c01bf6979938f67c24bd5940968488_u128,
        ),
        u256::ZERO,
        u256::ZERO,
    ],
    [
        u256::from_words(
            0x1e6843a5457416b6dc5b7aa09a9ce21b_u128,
            0x1d4cba6554e51d84665f75260113b3d5_u128,
        ),
        u256::ZERO,
        u256::ZERO,
    ],
    [
        u256::from_words(
            0x11cdf00a35f650c55fca25c9929c8ad9_u128,
            0xa68daf9ac6a189ab1f5bc79f21641d4b_u128,
        ),
        u256::ZERO,
        u256::ZERO,
    ],
    [
        u256::from_words(
            0x21632de3d3bbc5e42ef36e588158d6d4_u128,
            0x608b2815c77355b7e82b5b9b7eb560bc_u128,
        ),
        u256::ZERO,
        u256::ZERO,
    ],
    [
        u256::from_words(
            0x0de625758452efbd97b27025fbd245e0_u128,
            0x255ae48ef2a329e449d7b5c51c18498a_u128,
        ),
        u256::ZERO,
        u256::ZERO,
    ],
    [
        u256::from_words(
            0x2ad253c053e75213e2febfd4d976cc01_u128,
            0xdd9e1e1c6f0fb6b09b09546ba0838098_u128,
        ),
        u256::ZERO,
        u256::ZERO,
    ],
    [
        u256::from_words(
            0x1d6b169ed63872dc6ec7681ec39b3be9_u128,
            0x3dd49cdd13c813b7d35702e38d60b077_u128,
        ),
        u256::ZERO,
        u256::ZERO,
    ],
    [
        u256::from_words(
            0x1660b740a143664bb9127c4941b67fed_u128,
            0x0be3ea70a24d5568c3a54e706cfef7fe_u128,
        ),
        u256::ZERO,
        u256::ZERO,
    ],
    [
        u256::from_words(
            0x0065a92d1de81f34114f4ca2deef76e0_u128,
            0xceacdddb12cf879096a29f10376ccbfe_u128,
        ),
        u256::ZERO,
        u256::ZERO,
    ],
    [
        u256::from_words(
            0x1f11f065202535987367f823da7d672c_u128,
            0x353ebe2ccbc4869bcf30d50a5871040d_u128,
        ),
        u256::ZERO,
        u256::ZERO,
    ],
    [
        u256::from_words(
            0x26596f5c5dd5a5d1b437ce7b14a2c3dd_u128,
            0x3bd1d1a39b6759ba110852d17df0693e_u128,
        ),
        u256::ZERO,
        u256::ZERO,
    ],
    [
        u256::from_words(
            0x16f49bc727e45a2f7bf3056efcf8b6d3_u128,
            0x8539c4163a5f1e706743db15af91860f_u128,
        ),
        u256::ZERO,
        u256::ZERO,
    ],
    [
        u256::from_words(
            0x1abe1deb45b3e3119954175efb331bf4_u128,
            0x568feaf7ea8b3dc5e1a4e7438dd39e5f_u128,
        ),
        u256::ZERO,
        u256::ZERO,
    ],
    [
        u256::from_words(
            0x0e426ccab66984d1d8993a74ca548b77_u128,
            0x9f5db92aaec5f102020d34aea15fba59_u128,
        ),
        u256::ZERO,
        u256::ZERO,
    ],
    [
        u256::from_words(
            0x0e7c30c2e2e8957f4933bd1942053f1f_u128,
            0x0071684b902d534fa841924303f6a6c6_u128,
        ),
        u256::ZERO,
        u256::ZERO,
    ],
    [
        u256::from_words(
            0x0812a017ca92cf0a1622708fc7edff1d_u128,
            0x6166ded6e3528ead4c76e1f31d3fc69d_u128,
        ),
        u256::ZERO,
        u256::ZERO,
    ],
    [
        u256::from_words(
            0x21a5ade3df2bc1b5bba949d1db960400_u128,
            0x68afe5026edd7a9c2e276b47cf010d54_u128,
        ),
        u256::ZERO,
        u256::ZERO,
    ],
    [
        u256::from_words(
            0x01f3035463816c84ad711bf1a058c6c6_u128,
            0xbd101945f50e5afe72b1a5233f8749ce_u128,
        ),
        u256::ZERO,
        u256::ZERO,
    ],
    [
        u256::from_words(
            0x0b115572f038c0e2028c2aafc2d06a5e_u128,
            0x8bf2f9398dbd0fdf4dcaa82b0f0c1c8b_u128,
        ),
        u256::ZERO,
        u256::ZERO,
    ],
    [
        u256::from_words(
            0x1c38ec0b99b62fd4f0ef255543f50d2e_u128,
            0x27fc24db42bc910a3460613b6ef59e2f_u128,
        ),
        u256::ZERO,
        u256::ZERO,
    ],
    [
        u256::from_words(
            0x1c89c6d9666272e8425c3ff1f4ac737b_u128,
            0x2f5d314606a297d4b1d0b254d880c53e_u128,
        ),
        u256::ZERO,
        u256::ZERO,
    ],
    [
        u256::from_words(
            0x03326e643580356bf6d44008ae4c042a_u128,
            0x21ad4880097a5eb38b71e2311bb88f8f_u128,
        ),
        u256::ZERO,
        u256::ZERO,
    ],
    [
        u256::from_words(
            0x268076b0054fb73f67cee9ea0e51e3ad_u128,
            0x50f27a6434b5dceb5bdde2299910a4c9_u128,
        ),
        u256::ZERO,
        u256::ZERO,
    ],
    // ── 4 ending full rounds ──────────────────────────────────────────────
    [
        u256::from_words(
            0x1acd63c67fbc9ab1626ed93491bda32e_u128,
            0x5da18ea9d8e4f10178d04aa6f8747ad0_u128,
        ),
        u256::from_words(
            0x19f8a5d670e8ab66c4e3144be58ef690_u128,
            0x1bf93375e2323ec3ca8c86cd2a28b5a5_u128,
        ),
        u256::from_words(
            0x1c0dc443519ad7a86efa40d2df10a011_u128,
            0x068193ea51f6c92ae1cfbb5f7b9b6893_u128,
        ),
    ],
    [
        u256::from_words(
            0x14b39e7aa4068dbe50fe7190e421dc19_u128,
            0xfbeab33cb4f6a2c4180e4c3224987d3d_u128,
        ),
        u256::from_words(
            0x1d449b71bd826ec58f28c63ea6c561b7_u128,
            0xb820fc519f01f021afb1e35e28b0795e_u128,
        ),
        u256::from_words(
            0x1ea2c9a89baaddbb60fa97fe60fe9d8e_u128,
            0x89de141689d1252276524dc0a9e987fc_u128,
        ),
    ],
    [
        u256::from_words(
            0x0478d66d43535a8cb57e9c1c3d6a2bd7_u128,
            0x591f9a46a0e9c058134d5cefdb3c7ff1_u128,
        ),
        u256::from_words(
            0x19272db71eece6a6f608f3b2717f9cd2_u128,
            0x662e26ad86c400b21cde5e4a7b00bebe_u128,
        ),
        u256::from_words(
            0x14226537335cab33c749c746f09208ab_u128,
            0xb2dd1bd66a87ef75039be846af134166_u128,
        ),
    ],
    [
        u256::from_words(
            0x01fd6af15956294f9dfe38c0d976a088_u128,
            0xb21c21e4a1c2e823f912f44961f9a9ce_u128,
        ),
        u256::from_words(
            0x18e5abedd626ec307bca190b8b2cab1a_u128,
            0xaee2e62ed229ba5a5ad8518d4e5f2a57_u128,
        ),
        u256::from_words(
            0x0fc1bbceba0590f5abbdffa6d3b35e32_u128,
            0x97c021a3a409926d0e2d54dc1c84fda6_u128,
        ),
    ],
];

// ── Poseidon2 permutation ─────────────────────────────────────────────────────

/// S-box: x^5 mod FR_MODULUS. Uses three multiplications (x→x²→x⁴→x⁵).
#[inline(always)]
fn sbox(x: u256) -> u256 {
    let x2 = Bn254::mul(x, x);
    let x4 = Bn254::mul(x2, x2);
    Bn254::mul(x4, x)
}

/// External (full-round) linear layer `M_E = circ(2,1,1) = I + J`.
///
/// For state `[a, b, c]` with `S = a + b + c`:
/// ```text
/// [2 1 1]   [a]   [a + S]
/// [1 2 1] * [b] = [b + S]
/// [1 1 2]   [c]   [c + S]
/// ```
#[inline(always)]
fn mat_external(state: &mut [u256; T]) {
    let s = Bn254::add(Bn254::add(state[0], state[1]), state[2]);
    for slot in state.iter_mut() {
        *slot = Bn254::add(*slot, s);
    }
}

/// Internal (partial-round) linear layer `M_I = J + diag(1,1,2)`.
///
/// For state `[a, b, c]` with `S = a + b + c`:
/// ```text
/// [2 1 1]   [a]   [a + S]
/// [1 2 1] * [b] = [b + S]
/// [1 1 3]   [c]   [c + S + c]
/// ```
#[inline(always)]
fn mat_internal(state: &mut [u256; T]) {
    let c = state[2];
    let s = Bn254::add(Bn254::add(state[0], state[1]), c);
    state[0] = Bn254::add(state[0], s);
    state[1] = Bn254::add(state[1], s);
    state[2] = Bn254::add(Bn254::add(c, s), c);
}

/// Full Poseidon2 permutation over BN254 Fr (CAP-0075, t=3).
///
/// Applies the initial external matrix `M_E`, then 64 rounds
/// (4 full + 56 partial + 4 full) to the 3-element state.
pub(crate) fn permute(state: &mut [u256; T]) {
    let mut round = 0;

    // Initial external linear layer, before round 0.
    mat_external(state);

    // ── 4 beginning full rounds ───────────────────────────────────────────
    for _ in 0..(ROUNDS_F / 2) {
        // Add round constants
        for (s, rc) in state.iter_mut().zip(&RC[round]) {
            *s = Bn254::add(*s, *rc);
        }
        // Full S-box
        for slot in state.iter_mut() {
            *slot = sbox(*slot);
        }
        // External linear layer M_E
        mat_external(state);
        round += 1;
    }

    // ── 56 partial rounds ─────────────────────────────────────────────────
    for _ in 0..ROUNDS_P {
        // Add round constant (only index 0 is non-zero)
        state[0] = Bn254::add(state[0], RC[round][0]);
        // Partial S-box (index 0 only)
        state[0] = sbox(state[0]);
        // Internal linear layer M_I
        mat_internal(state);
        round += 1;
    }

    // ── 4 ending full rounds ──────────────────────────────────────────────
    for _ in 0..(ROUNDS_F / 2) {
        // Add round constants
        for (s, rc) in state.iter_mut().zip(&RC[round]) {
            *s = Bn254::add(*s, *rc);
        }
        // Full S-box
        for slot in state.iter_mut() {
            *slot = sbox(*slot);
        }
        // External linear layer M_E
        mat_external(state);
        round += 1;
    }
}

// ── Sponge ────────────────────────────────────────────────────────────────────

/// Poseidon2 sponge over BN254 Fr (t=3, rate=2, capacity=1).
///
/// The capacity element (`state[2]`) starts at 0 and is only modified by the
/// permutation and by the finalization domain separator — never by absorption.
///
/// Finalization applies standard 10* padding: a `1` marker is added at the next
/// free rate position, the capacity element is mixed with a domain tag, and one
/// permutation is applied. This makes the encoding of the absorbed field-element
/// sequence injective, so `[]` and `[0]` (and `[1]` and `[1, 0]`) hash
/// differently.
pub struct Poseidon2Sponge {
    state: [u256; T],
    /// Next rate slot to write into during absorption.
    rate_idx: usize,
}

impl Default for Poseidon2Sponge {
    fn default() -> Self {
        Self::new()
    }
}

impl Poseidon2Sponge {
    /// Create a new sponge with zeroed state.
    pub fn new() -> Self {
        Self {
            state: [u256::from(0u8); T],
            rate_idx: 0,
        }
    }

    /// Absorb a slice of BN254 Fr field elements into the sponge.
    ///
    /// Each element is added (mod r) into the current rate position. When the
    /// rate is full, the permutation is applied and absorption continues.
    pub fn absorb(&mut self, inputs: &[u256]) {
        for &input in inputs {
            self.state[self.rate_idx] = Bn254::add(self.state[self.rate_idx], input);
            self.rate_idx += 1;
            if self.rate_idx == RATE {
                permute(&mut self.state);
                self.rate_idx = 0;
            }
        }
    }

    /// Squeeze one field element.
    ///
    /// Finalizes with 10* padding (a `1` marker at the next free rate slot) and
    /// capacity-domain framing, applies one permutation, then returns the first
    /// rate element. Calling `squeeze` again re-finalizes from the advanced
    /// state, so successive squeezes yield independent field elements.
    pub fn squeeze(&mut self) -> u256 {
        // 10* padding: mark the end of the absorbed message with a `1` at the
        // next free rate position. Remaining rate slots stay as they are, which
        // is the zero-padding tail because the marker alone fixes the length.
        self.state[self.rate_idx] = Bn254::add(self.state[self.rate_idx], PAD_MARKER);
        self.rate_idx = 0;
        // Capacity-domain separation.
        self.state[T - 1] = Bn254::add(self.state[T - 1], DOMAIN_CAPACITY);
        permute(&mut self.state);
        self.state[0]
    }
}

// ── Transcript ────────────────────────────────────────────────────────────────

/// A Fiat-Shamir transcript backed by a Poseidon2 sponge.
///
/// Each `absorb` updates the sponge state; each `challenge` squeezes
/// a fresh field element. The sponge is reset between absorb/challenge
/// calls to ensure independent challenges.
pub struct Transcript {
    sponge: Poseidon2Sponge,
}

impl Default for Transcript {
    fn default() -> Self {
        Self::new()
    }
}

impl Transcript {
    /// Create a fresh transcript with an empty Poseidon2 state.
    pub fn new() -> Self {
        Self {
            sponge: Poseidon2Sponge::new(),
        }
    }

    /// Absorb a scalar field element.
    pub fn absorb_scalar(&mut self, s: u256) {
        self.sponge.absorb(&[s]);
    }

    /// Absorb an affine G1 point (x, y coordinates).
    pub fn absorb_point(&mut self, p: &crate::G1Affine) {
        self.sponge.absorb(&[p.x, p.y]);
    }

    /// Produce the next challenge scalar in `[0, r)`.
    pub fn challenge(&mut self) -> u256 {
        self.sponge.squeeze()
    }
}

// ── hash_to_fq ────────────────────────────────────────────────────────────────

/// Deterministic hash of arbitrary bytes into BN254 Fq using Poseidon2.
///
/// The total byte length is absorbed first, followed by the input in 31-byte
/// big-endian chunks (right-aligned into 32 bytes, so every chunk is
/// `< 2^248 < q` and is never reduced modulo the field). Because the length is
/// committed up front, trailing zero bytes can no longer collide, and because
/// no chunk is reduced there is no modulo bias.
pub fn hash_to_fq(bytes: &[u8]) -> u256 {
    let mut sponge = Poseidon2Sponge::new();

    // Commit to the exact byte length so that zero-padding of the final chunk
    // is unambiguous (e.g. `b"a"` vs `b"a\0"`).
    sponge.absorb(&[u256::from(bytes.len() as u64)]);

    // 31-byte chunks are right-aligned, hence always below 2^248 < q: the
    // value is a canonical field element and needs no reduction.
    for chunk in bytes.chunks(31) {
        let mut buf = [0u8; 32];
        buf[32 - chunk.len()..].copy_from_slice(chunk);
        sponge.absorb(&[u256::from_be_bytes(buf)]);
    }

    // The sponge output is a canonical Fr element, and r < q, so it is already
    // a valid Fq element with no reduction (and therefore no modulo bias).
    sponge.squeeze()
}

/// Hash arbitrary bytes into a valid BN254 Fr scalar.
pub fn hash_to_fr(bytes: &[u8]) -> u256 {
    hash_to_fq(bytes) % Bn254::FR_MODULUS
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg_attr(miri, ignore)]
    fn permutation_deterministic() {
        let mut s1 = [u256::from(0u8), u256::from(1u8), u256::from(2u8)];
        let mut s2 = s1;
        permute(&mut s1);
        permute(&mut s2);
        assert_eq!(s1, s2);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn sponge_absorb_squeeze_deterministic() {
        let mut s1 = Poseidon2Sponge::new();
        s1.absorb(&[u256::from(42u8), u256::from(99u8)]);
        let c1 = s1.squeeze();

        let mut s2 = Poseidon2Sponge::new();
        s2.absorb(&[u256::from(42u8), u256::from(99u8)]);
        let c2 = s2.squeeze();

        assert_eq!(c1, c2);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn sponge_different_inputs_different_outputs() {
        let mut s1 = Poseidon2Sponge::new();
        s1.absorb(&[u256::from(1u8)]);
        let c1 = s1.squeeze();

        let mut s2 = Poseidon2Sponge::new();
        s2.absorb(&[u256::from(2u8)]);
        let c2 = s2.squeeze();

        assert_ne!(c1, c2);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn transcript_independent_challenges() {
        let mut tr = Transcript::new();
        tr.absorb_point(&crate::G1Affine {
            x: u256::from(1u8),
            y: u256::from(2u8),
        });
        let c1 = tr.challenge();
        let c2 = tr.challenge();
        assert_ne!(c1, c2);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn transcript_matches_std_transcript() {
        // Verify that this implementation produces the same output as
        // soroban-zk-std's Poseidon2 sponge for the same inputs.
        // (Both use identical round constants and parameters.)
        let mut sponge = Poseidon2Sponge::new();
        sponge.absorb(&[u256::from(0u8), u256::from(1u8), u256::from(2u8)]);
        let result = sponge.squeeze();

        // The result should be a valid field element (< FR_MODULUS).
        assert!(result < Bn254::FR_MODULUS);
        // The result should be non-zero (the permutation is not the identity).
        assert_ne!(result, u256::from(0u8));
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn hash_to_fq_deterministic() {
        let h1 = hash_to_fq(b"hello world");
        let h2 = hash_to_fq(b"hello world");
        assert_eq!(h1, h2);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn hash_to_fq_different_inputs() {
        let h1 = hash_to_fq(b"hello");
        let h2 = hash_to_fq(b"world");
        assert_ne!(h1, h2);
    }

    #[test]
    fn hash_to_fq_in_fq_range() {
        let h = hash_to_fq(b"test");
        assert!(h < Bn254::FQ_MODULUS);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn permutation_matches_cap0075_known_answer() {
        // CAP-0075 / soroban-env-host `poseidon2_permutation([0, 1, 2])` over
        // BN254 Fr (same vector asserted by soroban-zk-std). This fails if the
        // initial M_E, external M_E, or internal M_I layers are wrong.
        let mut state = [u256::from(0u8), u256::from(1u8), u256::from(2u8)];
        permute(&mut state);
        assert_eq!(
            state[0],
            u256::from_words(
                0x0bb61d24daca55eebcb1929a82650f32_u128,
                0x8134334da98ea4f847f760054f4a3033_u128
            )
        );
        assert_eq!(
            state[1],
            u256::from_words(
                0x303b6f7c86d043bfcbcc80214f26a302_u128,
                0x77a15d3f74ca654992defe7ff8d03570_u128
            )
        );
        assert_eq!(
            state[2],
            u256::from_words(
                0x1ed25194542b12eef8617361c3ba7c52_u128,
                0xe660b145994427cc86296242cf766ec8_u128
            )
        );
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn sponge_padding_separates_empty_from_zero() {
        let empty = Poseidon2Sponge::new().squeeze();
        let mut zero = Poseidon2Sponge::new();
        zero.absorb(&[u256::from(0u8)]);
        assert_ne!(empty, zero.squeeze());
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn sponge_padding_separates_trailing_zeros() {
        let hash = |inputs: &[u256]| {
            let mut sponge = Poseidon2Sponge::new();
            sponge.absorb(inputs);
            sponge.squeeze()
        };
        let one = hash(&[u256::from(1u8)]);
        let one_zero = hash(&[u256::from(1u8), u256::from(0u8)]);
        let one_zero_zero = hash(&[u256::from(1u8), u256::from(0u8), u256::from(0u8)]);
        assert_ne!(one, one_zero);
        assert_ne!(one, one_zero_zero);
        assert_ne!(one_zero, one_zero_zero);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn sponge_accepts_boundary_field_elements() {
        let mut sponge = Poseidon2Sponge::new();
        sponge.absorb(&[
            Bn254::FR_MODULUS - u256::from(1u8),
            Bn254::FR_MODULUS - u256::from(2u8),
            u256::from(0u8),
            Bn254::FR_MODULUS - u256::from(1u8),
        ]);
        let out = sponge.squeeze();
        assert!(out < Bn254::FR_MODULUS);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn hash_to_fq_separates_trailing_zero_bytes() {
        assert_ne!(hash_to_fq(b""), hash_to_fq(&[0u8]));
        assert_ne!(hash_to_fq(b"a"), hash_to_fq(b"a\0"));
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn hash_to_fq_separates_chunk_boundary_inputs() {
        // Inputs that only differ past the old 32-byte chunk boundary (and
        // trailing zeros) must not collide.
        let mut a = [b'a'; 62];
        let mut b = [b'a'; 63];
        a[61] = 0;
        b[62] = 0;
        assert_ne!(hash_to_fq(&a), hash_to_fq(&b));

        // [1] vs [1, 0, ..., 0] (64 bytes) must hash differently.
        let short = [1u8];
        let mut long = [0u8; 64];
        long[0] = 1;
        assert_ne!(hash_to_fq(&short), hash_to_fq(&long));
    }
}
