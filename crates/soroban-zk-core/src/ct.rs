/// Constant-time primitives for side-channel resistance.
/// These functions ensure that the execution time and power consumption 
/// are independent of the values being processed.

/// A 256-bit unsigned integer. 
/// In a production ZK library, this is typically a wrapper around [u64; 4] 
/// or an external type like ethnum::u256.
use ethnum::u256; 

/// Selects between `a` and `b` in constant time.
/// Returns `a` if `condition` is true, and `b` if `condition` is false.
///
/// Logic:
/// 1. Convert `condition` to a u64 (0 or 1).
/// 2. Create a mask: -1 (0xFF...F) if 1, 0 if 0.
/// 3. Result = b ^ ((a ^ b) & mask)
#[inline(always)]
pub fn ct_select(condition: bool, a: u256, b: u256) -> u256 {
    // Convert bool to 0u64 or 1u64
    let cond_val = condition as u64;
    
    // Create a 64-bit mask. 
    // wrapping_neg(1) -> 0xFFFFFFFFFFFFFFFF
    // wrapping_neg(0) -> 0x0000000000000000
    let mask_64 = 0u64.wrapping_sub(cond_val);
    
    // Expand to 256-bit mask
    let mask = u256::from_words(mask_64, mask_64, mask_64, mask_64);
    
    // Branchless bitwise selection
    b ^ ((a ^ b) & mask)
}

/// Checks if two u256 values are equal in constant time.
/// Returns true if a == b, false otherwise.
#[inline(always)]
pub fn ct_eq(a: u256, b: u256) -> bool {
    ct_is_zero(a ^ b)
}

/// Checks if a u256 value is zero in constant time.
/// Returns true if a == 0, false otherwise.
#[inline(always)]
pub fn ct_is_zero(a: u256) -> bool {
    let words = a.into_words();
    // OR all 64-bit words together. If any bit is 1, 'combined' will be non-zero.
    let combined = words[0] | words[1] | words[2] | words[3];
    
    // Constant-time check: 
    // If combined is 0, (0 | -0) >> 63 is 0.
    // If combined is non-zero, (combined | -combined) >> 63 is 1.
    let is_nonzero_bit = (combined | combined.wrapping_neg()) >> 63;
    
    // Convert to boolean: 1 (nonzero) -> false, 0 (zero) -> true
    is_nonzero_bit == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ct_select() {
        let a = u256::from(0xAAAA_AAAA_AAAA_AAAA_u64);
        let b = u256::from(0x5555_5555_5555_5555_u64);

        assert_eq!(ct_select(true, a, b), a);
        assert_eq!(ct_select(false, a, b), b);

        // Boundary values
        let max = u256::MAX;
        let zero = u256::ZERO;
        assert_eq!(ct_select(true, max, zero), max);
        assert_eq!(ct_select(false, max, zero), zero);
    }

    #[test]
    fn test_ct_eq() {
        let a = u256::from(12345u64);
        let b = u256::from(12345u64);
        let c = u256::from(54321u64);

        assert!(ct_eq(a, b));
        assert!(!ct_eq(a, c));
        assert!(ct_eq(u256::MAX, u256::MAX));
        assert!(!ct_eq(u256::MAX, u256::ZERO));
    }

    #[test]
    fn test_ct_is_zero() {
        assert!(ct_is_zero(u256::ZERO));
        assert!(!ct_is_zero(u256::from(1u64)));
        assert!(!ct_is_zero(u256::MAX));
        
        // Test high-word zero check
        let hi_val = u256::from_words(0, 0, 0, 1);
        assert!(!ct_is_zero(hi_val));
    }
}
