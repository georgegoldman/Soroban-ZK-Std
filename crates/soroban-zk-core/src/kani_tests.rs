//! Kani bounded model-checking proofs for `soroban-zk-core`.
//!
//! Run with `cargo kani --package soroban-zk-core`.
//! Kani injects its own `kani` sysroot crate under `--cfg kani`; no external
//! `kani` crate dependency is required in `Cargo.toml`.

#[cfg(kani)]
mod proofs {
    use crate::sha256_padding;
    use crate::zeroize::SensitiveBuffer;
    use crate::*;

    #[inline(always)]
    fn any_u256() -> u256 {
        u256::from_words(kani::any::<u128>(), kani::any::<u128>())
    }

    /// Proves that CIOS/SOS Montgomery multiplication over BN254 `Fr` produces
    /// a canonical result strictly `< FR_MODULUS` for all inputs `< FR_MODULUS`,
    /// with zero arithmetic overflow and zero out-of-bounds limb accesses.
    #[kani::proof]
    #[kani::unwind(10)]
    fn verify_montgomery_mul_fr() {
        let a = any_u256();
        let b = any_u256();
        kani::assume(Bn254::is_valid_scalar(a));
        kani::assume(Bn254::is_valid_scalar(b));

        let res = from_limbs(&montgomery_mul(to_limbs(a), to_limbs(b), FR_N, FR_N0INV));
        assert!(Bn254::is_valid_scalar(res));
    }

    /// Proves that CIOS/SOS Montgomery multiplication over BN254 `Fq` produces
    /// a canonical result strictly `< FQ_MODULUS` for all inputs `< FQ_MODULUS`,
    /// with zero arithmetic overflow and zero out-of-bounds limb accesses.
    #[kani::proof]
    #[kani::unwind(10)]
    fn verify_montgomery_mul_fq() {
        let a = any_u256();
        let b = any_u256();
        kani::assume(Bn254::is_valid_fq(a));
        kani::assume(Bn254::is_valid_fq(b));

        let res = from_limbs(&montgomery_mul(to_limbs(a), to_limbs(b), FQ_N, FQ_N0INV));
        assert!(Bn254::is_valid_fq(res));
    }

    /// Proves lossless 256-bit <-> 4x64-bit limb round-trip and that 5-limb
    /// carry/borrow subtraction preserves ordering without underflow.
    #[kani::proof]
    fn verify_limb_conversion_and_carries() {
        let x = any_u256();
        assert_eq!(from_limbs(&to_limbs(x)), x);

        let a: Limbs5 = kani::any();
        let b: Limbs5 = kani::any();
        if limbs5_ge(&a, &b) {
            let mut diff = a;
            limbs5_sub_assign(&mut diff, &b);
            // Since a > b strictly, subtracting b cannot leave diff >= a when b > 0.
            if b != [0u64; 5] {
                assert!(limbs5_ge(&a, &diff));
            }
        }
    }

    /// Proves `Bn254::add` (Fr) canonicality, commutativity, and additive identity.
    #[kani::proof]
    fn verify_fr_add_ring_identities() {
        let a = any_u256();
        let b = any_u256();
        kani::assume(Bn254::is_valid_scalar(a));
        kani::assume(Bn254::is_valid_scalar(b));

        let sum = Bn254::add(a, b);
        assert!(Bn254::is_valid_scalar(sum));
        assert_eq!(sum, Bn254::add(b, a));
        assert_eq!(Bn254::add(a, u256::from(0u8)), a);
    }

    /// Proves `Bn254::sub` (Fr) canonicality, self-subtraction, additive identity,
    /// and exact inverse round-trips with `Bn254::add`.
    #[kani::proof]
    fn verify_fr_sub_ring_identities() {
        let a = any_u256();
        let b = any_u256();
        kani::assume(Bn254::is_valid_scalar(a));
        kani::assume(Bn254::is_valid_scalar(b));

        let diff = Bn254::sub(a, b);
        assert!(Bn254::is_valid_scalar(diff));
        assert_eq!(Bn254::sub(a, a), u256::from(0u8));
        assert_eq!(Bn254::sub(a, u256::from(0u8)), a);
        assert_eq!(Bn254::sub(Bn254::add(a, b), b), a);
        assert_eq!(Bn254::add(diff, b), a);
    }

    /// Proves `Bn254::add_fq` canonicality and commutativity.
    #[kani::proof]
    fn verify_fq_add() {
        let a = any_u256();
        let b = any_u256();
        kani::assume(Bn254::is_valid_fq(a));
        kani::assume(Bn254::is_valid_fq(b));

        let c = Bn254::add_fq(a, b);
        assert!(Bn254::is_valid_fq(c));
        assert_eq!(c, Bn254::add_fq(b, a));
    }

    /// Proves `Bn254::sub_fq` canonicality and additive inverse round-trip.
    #[kani::proof]
    fn verify_fq_sub() {
        let a = any_u256();
        let b = any_u256();
        kani::assume(Bn254::is_valid_fq(a));
        kani::assume(Bn254::is_valid_fq(b));

        let c = Bn254::sub_fq(a, b);
        assert!(Bn254::is_valid_fq(c));
        assert_eq!(Bn254::add_fq(c, b), a);
    }

    /// Proves scalar and base-field modulus boundary validation.
    #[kani::proof]
    fn verify_range_validation() {
        let val = any_u256();

        if val == Bn254::FR_MODULUS {
            assert!(!Bn254::is_valid_scalar(val));
        } else if val == Bn254::FR_MODULUS - u256::from(1u8) {
            assert!(Bn254::is_valid_scalar(val));
        } else if val == Bn254::FR_MODULUS + u256::from(1u8) {
            assert!(!Bn254::is_valid_scalar(val));
        }

        if val == Bn254::FQ_MODULUS {
            assert!(!Bn254::is_valid_fq(val));
        } else if val == Bn254::FQ_MODULUS - u256::from(1u8) {
            assert!(Bn254::is_valid_fq(val));
        }
    }

    /// Proves `sha256_padding::padded_length` alignment, minimality, overflow
    /// freedom, and out-of-range rejection for all `usize` inputs.
    #[kani::proof]
    fn verify_sha256_padded_length_invariants() {
        let input_len: usize = kani::any();
        match sha256_padding::padded_length(input_len) {
            Ok(padded) => {
                assert!(input_len <= sha256_padding::MAX_INPUT_BYTES);
                assert_eq!(padded % sha256_padding::BLOCK_SIZE, 0);
                let min_required = input_len + 9;
                assert!(padded >= min_required);
                assert!(padded - min_required < sha256_padding::BLOCK_SIZE);
            }
            Err(err) => {
                assert_eq!(err, ZkError::InvalidInput);
                assert!(input_len > sha256_padding::MAX_INPUT_BYTES);
            }
        }
    }

    /// Proves `SensitiveBuffer<u64>` unconditionally zeroes its stack slot on `Drop`.
    #[kani::proof]
    fn verify_sensitive_buffer_drop_zeroes_u64() {
        let secret: u64 = kani::any();
        let mut slot = core::mem::MaybeUninit::new(SensitiveBuffer::new(secret));
        unsafe {
            assert_eq!(*(*slot.as_ptr()).as_ref(), secret);
            core::ptr::drop_in_place(slot.as_mut_ptr());
            let after_drop = core::ptr::read_volatile(slot.as_ptr() as *const u64);
            assert_eq!(after_drop, 0u64);
        }
    }

    /// Proves `SensitiveBuffer<u256>` (32-byte scalar/field element) zeroes all
    /// 32 bytes of its stack slot on `Drop`.
    #[kani::proof]
    fn verify_sensitive_buffer_drop_zeroes_u256() {
        let secret = any_u256();
        let mut slot = core::mem::MaybeUninit::new(SensitiveBuffer::new(secret));
        unsafe {
            assert_eq!(*(*slot.as_ptr()).as_ref(), secret);
            core::ptr::drop_in_place(slot.as_mut_ptr());
            let bytes = core::ptr::read_volatile(slot.as_ptr() as *const [u8; 32]);
            assert_eq!(bytes, [0u8; 32]);
        }
    }
}

#[cfg(test)]
mod unit_tests {
    use crate::sha256_padding;
    use crate::zeroize::SensitiveBuffer;
    use crate::*;

    #[test]
    fn montgomery_mul_fr_boundary_values_stay_canonical() {
        let zero = u256::from(0u8);
        let one = u256::from(1u8);
        let max_fr = Bn254::FR_MODULUS - one;
        let samples = [zero, one, u256::from(2u8), max_fr - one, max_fr];

        for &a in &samples {
            for &b in &samples {
                let res = from_limbs(&montgomery_mul(to_limbs(a), to_limbs(b), FR_N, FR_N0INV));
                assert!(Bn254::is_valid_scalar(res));
            }
        }
    }

    #[test]
    fn montgomery_mul_fq_boundary_values_stay_canonical() {
        let zero = u256::from(0u8);
        let one = u256::from(1u8);
        let max_fq = Bn254::FQ_MODULUS - one;
        let samples = [zero, one, u256::from(2u8), max_fq - one, max_fq];

        for &a in &samples {
            for &b in &samples {
                let res = from_limbs(&montgomery_mul(to_limbs(a), to_limbs(b), FQ_N, FQ_N0INV));
                assert!(Bn254::is_valid_fq(res));
            }
        }
    }

    #[test]
    fn fr_add_sub_ring_identities_and_boundaries() {
        let zero = u256::from(0u8);
        let one = u256::from(1u8);
        let max_fr = Bn254::FR_MODULUS - one;
        let samples = [zero, one, u256::from(42u8), max_fr - one, max_fr];

        for &a in &samples {
            assert_eq!(Bn254::add(a, zero), a);
            assert_eq!(Bn254::sub(a, zero), a);
            assert_eq!(Bn254::sub(a, a), zero);
            for &b in &samples {
                let sum = Bn254::add(a, b);
                let diff = Bn254::sub(a, b);
                assert!(Bn254::is_valid_scalar(sum));
                assert!(Bn254::is_valid_scalar(diff));
                assert_eq!(sum, Bn254::add(b, a));
                assert_eq!(Bn254::sub(sum, b), a);
                assert_eq!(Bn254::add(diff, b), a);
            }
        }
    }

    #[test]
    fn sha256_padded_length_boundaries_and_rejection() {
        for len in [
            0usize,
            1,
            55,
            56,
            63,
            64,
            119,
            120,
            sha256_padding::MAX_INPUT_BYTES,
        ] {
            let padded = sha256_padding::padded_length(len).expect("valid length");
            assert_eq!(padded % sha256_padding::BLOCK_SIZE, 0);
            assert!(padded >= len + 9);
            assert!(padded - (len + 9) < sha256_padding::BLOCK_SIZE);
        }

        assert_eq!(
            sha256_padding::padded_length(sha256_padding::MAX_INPUT_BYTES + 1),
            Err(ZkError::InvalidInput)
        );
        assert_eq!(
            sha256_padding::padded_length(usize::MAX),
            Err(ZkError::InvalidInput)
        );
    }

    #[test]
    fn sensitive_buffer_drop_zeroes_u256_slot() {
        let secret = u256::from_words(0xdeadbeefcafebabe_u128, 0x0123456789abcdef_u128);
        let mut slot = core::mem::MaybeUninit::new(SensitiveBuffer::new(secret));
        unsafe {
            assert_eq!(*(*slot.as_ptr()).as_ref(), secret);
            core::ptr::drop_in_place(slot.as_mut_ptr());
            let bytes = core::ptr::read_volatile(slot.as_ptr() as *const [u8; 32]);
            assert_eq!(bytes, [0u8; 32]);
        }
    }
}
