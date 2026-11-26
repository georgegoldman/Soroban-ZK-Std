use ethnum::u256;
use serde_json::Value;
use soroban_zk_core::{Bn254, G1Affine, G2Projective};

const VECTORS: &str = include_str!("../../../tests/vectors/reference_vectors.json");

fn vectors() -> Value {
    serde_json::from_str(VECTORS).expect("reference vector JSON")
}

fn number(value: &Value) -> u256 {
    value
        .as_str()
        .expect("decimal vector value")
        .parse()
        .expect("valid u256 vector value")
}

fn pair(value: &Value) -> (u256, u256) {
    (number(&value[0]), number(&value[1]))
}

fn point_g1(value: &Value) -> G1Affine {
    G1Affine {
        x: number(&value[0]),
        y: number(&value[1]),
    }
}

fn fq2_inverse(value: (u256, u256)) -> (u256, u256) {
    let norm = Bn254::add_fq(
        Bn254::mul_fq(value.0, value.0),
        Bn254::mul_fq(value.1, value.1),
    );
    let inverse = Bn254::invert_fq(norm);
    (
        Bn254::mul_fq(value.0, inverse),
        Bn254::sub_fq(u256::ZERO, Bn254::mul_fq(value.1, inverse)),
    )
}

fn g2_affine(point: G2Projective) -> ((u256, u256), (u256, u256)) {
    if point.is_identity() {
        return ((u256::ZERO, u256::ZERO), (u256::ZERO, u256::ZERO));
    }
    let z_inv = fq2_inverse(point.z);
    let z_inv_sq = Bn254::fq2_mul(z_inv, z_inv);
    let z_inv_cube = Bn254::fq2_mul(z_inv_sq, z_inv);
    (
        Bn254::fq2_mul(point.x, z_inv_sq),
        Bn254::fq2_mul(point.y, z_inv_cube),
    )
}

fn assert_g2_eq(actual: ((u256, u256), (u256, u256)), expected: &Value) {
    assert_eq!(actual.0, pair(&expected[0]));
    assert_eq!(actual.1, pair(&expected[1]));
}

#[test]
#[cfg_attr(miri, ignore)]
fn field_and_curve_operations_match_python_vectors() {
    let vectors = vectors();
    let fr = &vectors["fr"];
    let fr_a = number(&fr["inputs"][0]);
    let fr_b = number(&fr["inputs"][1]);
    assert_eq!(Bn254::add(fr_a, fr_b), number(&fr["add"]));
    assert_eq!(Bn254::mul(fr_a, fr_b), number(&fr["mul"]));
    assert_eq!(Bn254::invert(fr_a), number(&fr["inv"]));

    let fq = &vectors["fq"];
    let fq_a = number(&fq["inputs"][0]);
    let fq_b = number(&fq["inputs"][1]);
    assert_eq!(Bn254::add_fq(fq_a, fq_b), number(&fq["add"]));
    assert_eq!(Bn254::mul_fq(fq_a, fq_b), number(&fq["mul"]));
    assert_eq!(Bn254::invert_fq(fq_a), number(&fq["inv"]));

    let g1 = &vectors["g1"];
    let point = point_g1(&g1["point"]);
    assert_eq!(point.add(&point), point_g1(&g1["add"]));
    assert_eq!(point.add(&point), point_g1(&g1["double"]));
    assert_eq!(
        point.scalar_mul(number(&g1["scalar"])),
        point_g1(&g1["scalar_mul"])
    );

    let g2 = &vectors["g2"];
    let generator = G2Projective {
        x: pair(&g2["point"][0]),
        y: pair(&g2["point"][1]),
        z: (u256::from(1u8), u256::ZERO),
    };
    assert_g2_eq(g2_affine(generator.add(&generator)), &g2["add"]);
    assert_g2_eq(g2_affine(generator.double()), &g2["double"]);
    assert_g2_eq(
        g2_affine(Bn254::g2_scalar_mul(
            generator,
            number(&g2["scalar"]),
        )),
        &g2["scalar_mul"],
    );
}

#[test]
#[cfg_attr(miri, ignore)]
fn poseidon2_hash_outputs_match_python_vectors() {
    let vectors = vectors();
    let hash = &vectors["poseidon2"];
    let input = hash["hash_input_utf8"].as_str().expect("UTF-8 input");
    let bytes = input.as_bytes();
    assert_eq!(
        soroban_zk_core::poseidon2::hash_to_fq(bytes),
        number(&hash["hash_to_fq"])
    );
    assert_eq!(
        soroban_zk_core::poseidon2::hash_to_fr(bytes),
        number(&hash["hash_to_fr"])
    );
}
