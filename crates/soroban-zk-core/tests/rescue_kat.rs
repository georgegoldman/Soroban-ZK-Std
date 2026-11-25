//! Rescue-Prime Python reference cross-check vectors (Issue #454).
//!
//! All expected matrices, round keys, single-round intermediate states, and
//! full 6-round / iterated permutation outputs in this file were generated
//! independently by `scripts/rescue_prime_reference.py` over BN254 `Fr`
//! (IACR ePrint 2020/1143).

use ethnum::u256;
use soroban_zk_core::rescue::{
    mds_multiply, sbox_alpha, sbox_alpha_inv, MdsMat, RescuePrimeCore, ROUNDS, STATE,
};
use soroban_zk_core::Bn254;

const PY_MDS: [[u256; STATE]; STATE] = [
    [
        u256::from_words(
            0x10216f7ba065e00de81ac1e7808072c9_u128,
            0xb8114d6d7de87adb16a0a73150000000_u128,
        ),
        u256::from_words(
            0x0c19139cb84c680a6e14116da0605617_u128,
            0x4a0cfa121e6e5c2450f87d64fc000000_u128,
        ),
        u256::from_words(
            0x1d08fbde871dc67f6e96903a4db401d1_u128,
            0x7e858b5eaf6f438a5bedf9bf2999999a_u128,
        ),
    ],
    [
        u256::from_words(
            0x183227397098d014dc2822db40c0ac2e_u128,
            0x9419f4243cdcb848a1f0fac9f8000000_u128,
        ),
        u256::from_words(
            0x10216f7ba065e00de81ac1e7808072c9_u128,
            0xb8114d6d7de87adb16a0a73150000000_u128,
        ),
        u256::from_words(
            0x0c19139cb84c680a6e14116da0605617_u128,
            0x4a0cfa121e6e5c2450f87d64fc000000_u128,
        ),
    ],
    [
        u256::from_words(
            0x30644e72e131a029b85045b68181585d_u128,
            0x2833e84879b9709143e1f593f0000000_u128,
        ),
        u256::from_words(
            0x183227397098d014dc2822db40c0ac2e_u128,
            0x9419f4243cdcb848a1f0fac9f8000000_u128,
        ),
        u256::from_words(
            0x10216f7ba065e00de81ac1e7808072c9_u128,
            0xb8114d6d7de87adb16a0a73150000000_u128,
        ),
    ],
];

const PY_ROUND_KEYS: [[u256; STATE]; 2 * ROUNDS] = [
    [
        u256::from_words(
            0x241214b64e37a42dddc49216b6433fe7_u128,
            0x5e4af3533a8c8961def18b459420ce96_u128,
        ),
        u256::from_words(
            0x149e9522e80164b39561a6d532ed480d_u128,
            0xdb16db399fce8f2b72c8640bed14edd8_u128,
        ),
        u256::from_words(
            0x16e6151eb7f6065df49647b709fcde48_u128,
            0x6776be1e372155e42ce9c91b49342af3_u128,
        ),
    ],
    [
        u256::from_words(
            0x0b29463b35fc98ca03baae98f5d4f251_u128,
            0xd38e091fa179fbe1f10e77e0f46399cd_u128,
        ),
        u256::from_words(
            0x1a892f66364b75798cebe8e3ef3bf830_u128,
            0xf85ecb833f3b1023f4e90d2fc67a88d9_u128,
        ),
        u256::from_words(
            0x27af8ef16eb7a0535a73aaa4273ea081_u128,
            0x1b95b6f288e3b18e91ea29857a35f4df_u128,
        ),
    ],
    [
        u256::from_words(
            0x03546ef6134d6bcfac31bfdcc2118362_u128,
            0x03a559b0e04b314ff40642b72b1f22b9_u128,
        ),
        u256::from_words(
            0x15392eceb2d870dcedce619bd4a4baf5_u128,
            0x140dfe1390fcb22d89787f5631f4756d_u128,
        ),
        u256::from_words(
            0x238fa99e483edf2d219d37dcf824e86e_u128,
            0xd4fc7b384a4fecc8a0f5c8109fa0d0e7_u128,
        ),
    ],
    [
        u256::from_words(
            0x00bf1355bb7cfb01c74f7188922e6120_u128,
            0xa8c24b612471653b59ac1aff07d44f46_u128,
        ),
        u256::from_words(
            0x16af47292baf23e76016f26496f6c73d_u128,
            0x3c38f4b1791f3b8762f7f15b89acc9a3_u128,
        ),
        u256::from_words(
            0x105a902eafac24043e91c89164e510e1_u128,
            0xd7d1948c5660b56c7f6f7672dbe60b75_u128,
        ),
    ],
    [
        u256::from_words(
            0x0d7bc0cc3063a9d7c2b85c953ac460a7_u128,
            0x9e70b3ac3fef6f7952658a59cce56cce_u128,
        ),
        u256::from_words(
            0x205aa50ee2dc005f22a93fd5070636e2_u128,
            0x0406843871f8eb4bfce2845e060df6c1_u128,
        ),
        u256::from_words(
            0x0115db7f2494ba498f5168807e455811_u128,
            0xe55f92d6b48117dd75791b94b0d2e42f_u128,
        ),
    ],
    [
        u256::from_words(
            0x116ee19eba3b6f6f24d41133d4cc4d6b_u128,
            0x22d940b45256d7fb55f7a2bbc56fe585_u128,
        ),
        u256::from_words(
            0x1def0328023519e98741d1bf42429a1d_u128,
            0xdf9853579b3a59424184c12d0137c33c_u128,
        ),
        u256::from_words(
            0x005746d2203f013e44ac7cd2ca4f7025_u128,
            0x881a574932e81ee15125558032ca2d9b_u128,
        ),
    ],
    [
        u256::from_words(
            0x2c7c456a9d460f23f299aa3255995989_u128,
            0x47fb9289a8d9743efa621cea723cfb8b_u128,
        ),
        u256::from_words(
            0x04f971670f113c12f3e59a3bf8c32a9d_u128,
            0x71526bd9ff1ca7933bcf42f57cbe9142_u128,
        ),
        u256::from_words(
            0x1ba8e88c0c59e257fce11428c76c7d5d_u128,
            0x35b5a773d6c7da2609869306e43d0959_u128,
        ),
    ],
    [
        u256::from_words(
            0x00762d2d87b03a76a8851f6f5a69d3a6_u128,
            0x078a8be5028f962098da7be06012a7bc_u128,
        ),
        u256::from_words(
            0x23d7c7a4017398ef348dbb6b4d9f531b_u128,
            0x0757ad6050704bc7641be4492cf3ca0f_u128,
        ),
        u256::from_words(
            0x0a9cccd695ee8ad147aa245d3d7a30cf_u128,
            0xc0e0ab6072910d02cc00cf978ca0a89e_u128,
        ),
    ],
    [
        u256::from_words(
            0x0a0f24024b1fb9b5afd2997d5e3f1793_u128,
            0xf99e3f0bccb54dadefddd77b7a42a058_u128,
        ),
        u256::from_words(
            0x024e7d70b40332e5e0d5c790f244ce16_u128,
            0x85c3062776a792d6144385d1031c6a76_u128,
        ),
        u256::from_words(
            0x0f3e9d716963356b6f4d6c59b5ba5ddc_u128,
            0xcbe583b556a5466e6a8f2d444191542b_u128,
        ),
    ],
    [
        u256::from_words(
            0x1fb906fad59abc852df6bad6e47237de_u128,
            0x825ec36ba13efc46f29a4c8dd680bcaa_u128,
        ),
        u256::from_words(
            0x282fe85ec5d4b5bf5ac6dce1e237e078_u128,
            0xd107b69b35fe263e295b41a707cb9b42_u128,
        ),
        u256::from_words(
            0x0dee9f78d30ebbcabc8dc0ef1bda1e0a_u128,
            0x665c218fc9e1d6a1446cc9c8a765015a_u128,
        ),
    ],
    [
        u256::from_words(
            0x18d28d7bea35db5e6ddacd576186bc4a_u128,
            0xae4485f623b49fe505a94054ba75ef0e_u128,
        ),
        u256::from_words(
            0x0cc59f4f8d39b3ac4f2567bc56eb2c7e_u128,
            0x8da5550a0c04818b42fe695f8f285c20_u128,
        ),
        u256::from_words(
            0x1f1ef239cea48c9aaafcb216b0e08e5f_u128,
            0xd68cbea8eda24235a6f0ce2c85609659_u128,
        ),
    ],
    [
        u256::from_words(
            0x19832475410c38053d6b7085501edf21_u128,
            0x5741207e4bc9548afe8b4b179b9fa253_u128,
        ),
        u256::from_words(
            0x28f1800567daedaa3673eaa304d90334_u128,
            0xd616dcc9b6a093df07fab20251d2f27a_u128,
        ),
        u256::from_words(
            0x293042c65e37a4efb3190692bc75c547_u128,
            0x0076513c77b87b9d3535c10f1c5ed68f_u128,
        ),
    ],
];

fn run_single_round(core: &RescuePrimeCore, state: &mut [u256; STATE], round: usize) {
    for s in state.iter_mut() {
        *s = core.sbox_fwd(*s);
    }
    for i in 0..STATE {
        state[i] = Bn254::add(state[i], core.round_keys[2 * round][i]);
    }
    mds_multiply(&core.mds, state);

    for s in state.iter_mut() {
        *s = core.sbox_inv(*s);
    }
    for i in 0..STATE {
        state[i] = Bn254::add(state[i], core.round_keys[2 * round + 1][i]);
    }
    mds_multiply(&core.mds, state);
}

#[test]
fn rescue_constants_match_python_reference() {
    assert_eq!(sbox_alpha(), u256::from(5u8));
    assert_eq!(
        sbox_alpha_inv(),
        u256::from_words(
            0x26b6a528b427b35493736af8679aad17_u128,
            0x535cb9d394945a0dcfe7f7a98ccccccd_u128,
        )
    );

    let core = RescuePrimeCore::new();
    for (i, expected_row) in PY_MDS.iter().enumerate() {
        assert_eq!(core.mds.row(i), expected_row, "MDS row {i} mismatch");
    }
    assert_eq!(
        core.round_keys, PY_ROUND_KEYS,
        "SHAKE-256 round keys mismatch"
    );
}

#[test]
#[cfg_attr(miri, ignore)]
fn mds_multiply_matches_python_reference() {
    let mds = MdsMat::cauchy();

    let mut s1 = [u256::from(1u8), u256::from(2u8), u256::from(3u8)];
    mds_multiply(&mds, &mut s1);
    assert_eq!(
        s1,
        [
            u256::from_words(
                0x1ea5ed6ae3f4c34d9f660a04a75a73b2_u128,
                0x7754131cd5a01ca04497a410e4cccccc_u128,
            ),
            u256::from_words(
                0x2c5bf293f91828263e49953ca1613baa_u128,
                0xba2f94ed1a3f51da7e39cbc79bffffff_u128,
            ),
            u256::from_words(
                0x30644e72e131a029b85045b68181585d_u128,
                0x2833e84879b9709143e1f593effffffe_u128,
            ),
        ]
    );

    let mut s2 = [
        Bn254::FR_MODULUS - u256::ONE,
        Bn254::FR_MODULUS - u256::from(2u8),
        Bn254::FR_MODULUS - u256::from(3u8),
    ];
    mds_multiply(&mds, &mut s2);
    assert_eq!(
        s2,
        [
            u256::from_words(
                0x11be6107fd3cdcdc18ea3bb1da26e4aa_u128,
                0xb0dfd52ba41953f0ff4a51830b333335_u128,
            ),
            u256::from_words(
                0x04085bdee81978037a06b079e0201cb2_u128,
                0x6e04535b5f7a1eb6c5a829cc54000002_u128,
            ),
            u256::from_words(
                0x00000000000000000000000000000000_u128,
                0x00000000000000000000000000000003_u128,
            ),
        ]
    );
}

#[test]
#[cfg_attr(miri, ignore)]
fn rescue_round0_and_full_permute_match_python_reference() {
    let core = RescuePrimeCore::new();

    // 1. All-zero initial state: round 0, full permute, and permute^2.
    let mut z_r0 = [u256::ZERO; STATE];
    run_single_round(&core, &mut z_r0, 0);
    assert_eq!(
        z_r0,
        [
            u256::from_words(
                0x195435dd38b4af3a6b620ffa996544c8_u128,
                0x45cb4db47442cd96efacffb28d1386be_u128,
            ),
            u256::from_words(
                0x0f03b23dfc7d5235879ad26e59af9368_u128,
                0xaee853cb0d62110d455683b8439dd14f_u128,
            ),
            u256::from_words(
                0x2d6d8005832f9f0308df1230d2c70dde_u128,
                0xafec0ec48b9d76d195f2b2ffda517ba5_u128,
            ),
        ]
    );

    let mut z = [u256::ZERO; STATE];
    core.permute(&mut z);
    assert_eq!(
        z,
        [
            u256::from_words(
                0x1c46e3ccd382d9197c8cd86427ebd063_u128,
                0xc1f2027406e4145dd5e49773ed3e092e_u128,
            ),
            u256::from_words(
                0x131dea29d3bff388bad9363664dca54c_u128,
                0x1c3904f3bcb55490e8a005c972d2ff64_u128,
            ),
            u256::from_words(
                0x10140c23b75f77bf4ec508ca519e16e7_u128,
                0xc22b65576bd81c6cfabd5f01f036a360_u128,
            ),
        ]
    );

    core.permute(&mut z);
    assert_eq!(
        z,
        [
            u256::from_words(
                0x2ac21a55718ffc925509e9b0e4cefe14_u128,
                0x05e0281b3cc12e1df65ca5df7cdab0e4_u128,
            ),
            u256::from_words(
                0x2529ed0cde25d1152f3701d8b3ac06ef_u128,
                0x807b3d56032ca22291396e945b092790_u128,
            ),
            u256::from_words(
                0x1ce6a7adc2b2a28d0e096455706f3913_u128,
                0xa4740f04de6cc762f4a6d527a01d1ecd_u128,
            ),
        ]
    );

    // 2. Sequential [1, 2, 3]: round 0, full permute, and permute^2.
    let mut seq_r0 = [u256::from(1u8), u256::from(2u8), u256::from(3u8)];
    run_single_round(&core, &mut seq_r0, 0);
    assert_eq!(
        seq_r0,
        [
            u256::from_words(
                0x2d737172e37a89568415c1cd1775e1c2_u128,
                0xe794003d5a5284e60c7224c82b126c99_u128,
            ),
            u256::from_words(
                0x1acee33021370fd6e178e33f0638af1b_u128,
                0xbbc8eacb8f43260dcdb55c1d7a0da48d_u128,
            ),
            u256::from_words(
                0x0170b80bc390472b8bcdb7021283ac27_u128,
                0x67f577280e44af356eeb06e5bf773ba8_u128,
            ),
        ]
    );

    let mut seq = [u256::from(1u8), u256::from(2u8), u256::from(3u8)];
    core.permute(&mut seq);
    assert_eq!(
        seq,
        [
            u256::from_words(
                0x0f41a1a83517a6868cfd29c9cb049d5a_u128,
                0x3d1a545b966c592eb7f5b12f5c9c9314_u128,
            ),
            u256::from_words(
                0x227039662dc2df70cf31d8fb94dbc29b_u128,
                0x9ed8ebbbed3698d44ecfe5d452471327_u128,
            ),
            u256::from_words(
                0x1c81efcd19e26b5d96d931992c70d6fc_u128,
                0xb96fad2c3c86c07028234ad1ebc1ee98_u128,
            ),
        ]
    );

    core.permute(&mut seq);
    assert_eq!(
        seq,
        [
            u256::from_words(
                0x25e1bbffc6f05182000d66e8e31b2ed5_u128,
                0xf31a9e8a3332e53c426ed57f972bd6f7_u128,
            ),
            u256::from_words(
                0x16eec800ff9e1ee64a813960f187c655_u128,
                0x76e440226818161bc5309545c945e9db_u128,
            ),
            u256::from_words(
                0x0649efe01702444af508edcec18a21cf_u128,
                0x99ebb86e4dcbdb09d78c825cae010bed_u128,
            ),
        ]
    );

    // 3. Near-modulus boundary state [FR_MODULUS - 1, FR_MODULUS - 2, 42].
    let boundary_init = [
        Bn254::FR_MODULUS - u256::ONE,
        Bn254::FR_MODULUS - u256::from(2u8),
        u256::from(42u8),
    ];
    let mut b_r0 = boundary_init;
    run_single_round(&core, &mut b_r0, 0);
    assert_eq!(
        b_r0,
        [
            u256::from_words(
                0x02c723f1fd51a6ca4441b82f83e8a624_u128,
                0x5b81cf58ab4b3d365fa9129bab34723c_u128,
            ),
            u256::from_words(
                0x2e70c5a38e0f4eb1f603fe454557f2dd_u128,
                0xf9485533433e4ad675f8bd3842afa4a9_u128,
            ),
            u256::from_words(
                0x0e3213151c363769f58d632551e1fc29_u128,
                0x42bec5394283a5708a40c01f3858b76f_u128,
            ),
        ]
    );

    let mut b = boundary_init;
    core.permute(&mut b);
    assert_eq!(
        b,
        [
            u256::from_words(
                0x27910dabc4999be5bfd6762e3da29a1a_u128,
                0x27b48d0abed9674ad26e4077132da7f5_u128,
            ),
            u256::from_words(
                0x0a866a74a64407f25a6ab883ffe70eba_u128,
                0xd3edf827a3079b2ac567ae9966c19e2a_u128,
            ),
            u256::from_words(
                0x2bbbc22ae99d9f45bd0fcfdae04da86b_u128,
                0x68d67ea11c5beabdf1b7cd5523e15f64_u128,
            ),
        ]
    );

    core.permute(&mut b);
    assert_eq!(
        b,
        [
            u256::from_words(
                0x255e266f1a2767a37084ab1a6d1e4e21_u128,
                0x03cc29bef07397e6fb1f6852148f913f_u128,
            ),
            u256::from_words(
                0x0649f78715cf6c1e7f64482258b826ab_u128,
                0xc12c9622e48a30677b21a1219f176acb_u128,
            ),
            u256::from_words(
                0x05f43814eda56026efc7f31f33108883_u128,
                0x20b53bd0b19831f1a1f7826389c4a937_u128,
            ),
        ]
    );
}
