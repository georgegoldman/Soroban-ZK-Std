use ethnum::u256;
use soroban_zk_core::{kzg_commit, Bn254, DensePolynomial, G1Affine, G1Projective, ZkError};

/// BN254 G1 generator (x=1, y=2).
fn g1_generator() -> G1Affine {
    G1Affine {
        x: u256::from(1u8),
        y: u256::from(2u8),
    }
}

/// 2*G on BN254.
fn g1_two() -> G1Affine {
    G1Projective::from(g1_generator()).double().to_affine()
}

/// 3*G on BN254.
fn g1_three() -> G1Affine {
    G1Projective::from(g1_generator())
        .double()
        .add(&G1Projective::from(g1_generator()))
        .to_affine()
}

/// KZG with a single coefficient: C = a * G.
#[test]
fn kzg_single_coefficient() {
    let srs = [g1_generator()];
    let poly = DensePolynomial::<4>::from_coefficients_slice(&[u256::from(3u8)]).unwrap();

    let commitment = kzg_commit(&poly, &srs).unwrap();

    // 3*G
    let expected = g1_three();
    assert_eq!(commitment, expected);
}

/// KZG with two coefficients: C = a0*G1 + a1*G2.
#[test]
fn kzg_two_coefficients() {
    let srs = [g1_generator(), g1_two()];
    let poly =
        DensePolynomial::<4>::from_coefficients_slice(&[u256::from(2u8), u256::from(1u8)]).unwrap();

    let commitment = kzg_commit(&poly, &srs).unwrap();

    // 2*G + 1*(2*G) = 2*G + 2*G = 4*G
    let two_g = g1_two();
    let expected = two_g.add(&two_g);
    assert_eq!(commitment, expected);
}

/// KZG with zero polynomial returns the group identity.
#[test]
fn kzg_zero_polynomial() {
    let srs = [g1_generator()];
    let poly = DensePolynomial::<4>::zero();

    let commitment = kzg_commit(&poly, &srs).unwrap();

    // Identity: (0, 0)
    assert_eq!(commitment.x, u256::from(0u8));
    assert_eq!(commitment.y, u256::from(0u8));
}

/// KZG returns error when polynomial is longer than SRS.
#[test]
fn kzg_rejects_polynomial_exceeding_srs_length() {
    let srs = [g1_generator()];
    let poly =
        DensePolynomial::<4>::from_coefficients_slice(&[u256::from(1u8), u256::from(1u8)]).unwrap();

    assert_eq!(kzg_commit(&poly, &srs), Err(ZkError::InvalidInput));
}

/// KZG with constant polynomial (degree 0): C = a0 * G.
#[test]
fn kzg_constant_polynomial() {
    let srs = [g1_generator()];
    let poly = DensePolynomial::<4>::from_coefficients_slice(&[u256::from(5u8)]).unwrap();

    let commitment = kzg_commit(&poly, &srs).unwrap();

    // 5*G = 2*G + 3*G
    let expected = g1_two().add(&g1_three());
    assert_eq!(commitment, expected);
}

/// KZG with all-zero coefficients (trailing zeros stripped) behaves same as shorter polynomial.
#[test]
fn kzg_trailing_zeros_stripped() {
    let srs = [g1_generator(), g1_two()];
    let poly =
        DensePolynomial::<4>::from_coefficients_slice(&[u256::from(1u8), u256::from(0u8)]).unwrap();

    let commitment = kzg_commit(&poly, &srs).unwrap();

    // Only a0=1 matters: C = 1*G
    let expected = g1_generator();
    assert_eq!(commitment, expected);
}

/// KZG is linear: commit(f + g) == commit(f) + commit(g).
#[test]
fn kzg_linearity() {
    let srs = [g1_generator(), g1_two()];

    let poly_a =
        DensePolynomial::<4>::from_coefficients_slice(&[u256::from(1u8), u256::from(2u8)]).unwrap();
    let poly_b =
        DensePolynomial::<4>::from_coefficients_slice(&[u256::from(3u8), u256::from(4u8)]).unwrap();

    let commit_a = kzg_commit(&poly_a, &srs).unwrap();
    let commit_b = kzg_commit(&poly_b, &srs).unwrap();
    let expected = commit_a.add(&commit_b);

    // f + g = [4, 6]
    let poly_sum =
        DensePolynomial::<4>::from_coefficients_slice(&[u256::from(4u8), u256::from(6u8)]).unwrap();
    let commit_sum = kzg_commit(&poly_sum, &srs).unwrap();

    assert_eq!(commit_sum, expected);
}

/// KZG is homomorphic: commit(c * f) == c * commit(f).
#[test]
fn kzg_homomorphism() {
    let srs = [g1_generator(), g1_two()];

    let poly =
        DensePolynomial::<4>::from_coefficients_slice(&[u256::from(2u8), u256::from(3u8)]).unwrap();
    let scalar = u256::from(4u8);

    let commit_f = kzg_commit(&poly, &srs).unwrap();
    let expected = Bn254::g1_scalar_mul(G1Projective::from(commit_f), scalar).to_affine();

    // scalar * poly = [8, 12]
    let poly_scaled =
        DensePolynomial::<4>::from_coefficients_slice(&[u256::from(8u8), u256::from(12u8)])
            .unwrap();
    let commit_scaled = kzg_commit(&poly_scaled, &srs).unwrap();

    assert_eq!(commit_scaled, expected);
}
