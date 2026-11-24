#[cfg(kani)]
mod tests {
    use crate::*;

    #[inline(always)]
    fn any_u256() -> u256 {
        u256::from_words(kani::any::<u128>(), kani::any::<u128>())
    }

    #[kani::proof]
    fn verify_fr_add() {
        let a = any_u256();
        let b = any_u256();
        kani::assume(Bn254::is_valid_scalar(a));
        kani::assume(Bn254::is_valid_scalar(b));

        let c = Bn254::add(a, b);
        assert!(Bn254::is_valid_scalar(c));
    }

    #[kani::proof]
    fn verify_fq_add() {
        let a = any_u256();
        let b = any_u256();
        kani::assume(Bn254::is_valid_fq(a));
        kani::assume(Bn254::is_valid_fq(b));

        let c = Bn254::add_fq(a, b);
        assert!(Bn254::is_valid_fq(c));
    }

    #[kani::proof]
    fn verify_fq_sub() {
        let a = any_u256();
        let b = any_u256();
        kani::assume(Bn254::is_valid_fq(a));
        kani::assume(Bn254::is_valid_fq(b));

        let c = Bn254::sub_fq(a, b);
        assert!(Bn254::is_valid_fq(c));
    }

    #[kani::proof]
    fn verify_foreign_limbs() {
        let a = any_u256();
        kani::assume(a < (u256::from(1u8) << 64));

        let b = any_u256();
        kani::assume(b < (u256::from(1u8) << 64));

        let c = a + b;
        assert!(c < (u256::from(1u8) << 65));
    }

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
    }

    #[kani::proof]
    fn verify_sensitive_buffer_drop_zeroes() {
        let secret: u64 = kani::any();
        let mut slot = core::mem::MaybeUninit::new(crate::zeroize::SensitiveBuffer::new(secret));
        unsafe {
            assert_eq!(*(*slot.as_ptr()).as_ref(), secret);
            core::ptr::drop_in_place(slot.as_mut_ptr());
            let after_drop = core::ptr::read_volatile(slot.as_ptr() as *const u64);
            assert_eq!(after_drop, 0u64);
        }
    }
}
