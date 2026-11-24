//! Cryptographic memory hygiene primitives (Issue #466).
//!
//! Provides [`SensitiveBuffer`], a `no_std`-compatible RAII wrapper that
//! unconditionally zeroes its contents through `core::ptr::write_volatile`
//! on `Drop`.  Using `write_volatile` prevents the compiler from eliding the
//! zero-fill as a "dead store" optimisation — a well-known pitfall when wiping
//! secrets in `no_std` environments where the `zeroize` crate is unavailable.
//!
//! ## Scope
//! This module intentionally covers **stack-resident, fixed-size** types —
//! primarily field scalars (`u256`), curve points (`G1Affine`), and short
//! arrays thereof.  Heap-resident sensitive data lives in a Soroban host
//! `Bytes` object (never directly accessible to guest code), so host-side
//! wiping is handled implicitly by the transaction rollback mechanism.
//!
//! ## Usage
//! ```ignore
//! let mut buf = SensitiveBuffer::new(my_scalar);
//! // … use `buf.as_ref()` / `buf.as_mut()` …
//! // `buf` is dropped here, and the scalar is zero-filled automatically.
//! ```
//!
//! ## Constant-Time Note
//! The zero-fill itself is not constant-time with respect to the *value* of
//! the secret — it always writes `N` zero bytes regardless.  The volatile
//! barrier prevents dead-store elimination, fulfilling the hygiene goal.  For
//! timing side-channel resistance in *arithmetic* operations see the wider
//! constant-time guarantees documented in `soroban-zk-core::Bn254`.

use core::mem;
use core::ptr;

/// A RAII guard that holds a value of type `T` and zeroes its bytes
/// unconditionally when dropped.
///
/// `T` must be `Copy` (i.e. it lives entirely on the stack or in a fixed
/// inline buffer) and `Sized` so that `mem::size_of::<T>()` is known at
/// compile time.
///
/// ```ignore
/// # use soroban_zk_core::zeroize::SensitiveBuffer;
/// let buf = SensitiveBuffer::new(42u64);
/// assert_eq!(*buf.as_ref(), 42u64);
/// // When `buf` goes out of scope the 8 bytes are zeroed via volatile write.
/// ```
pub struct SensitiveBuffer<T: Copy> {
    inner: T,
}

impl<T: Copy> SensitiveBuffer<T> {
    /// Wraps `value` in a [`SensitiveBuffer`].  No copy or allocation occurs
    /// beyond moving the value onto the stack.
    #[inline(always)]
    pub fn new(value: T) -> Self {
        Self { inner: value }
    }

    /// Returns a shared reference to the wrapped value.
    #[inline(always)]
    pub fn as_ref(&self) -> &T {
        &self.inner
    }

    /// Returns a mutable reference to the wrapped value.
    #[inline(always)]
    pub fn as_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    /// Consumes the guard without zeroing — use only when you are certain the
    /// value is no longer sensitive (e.g. after it has already been published
    /// as a public output).
    #[inline(always)]
    pub fn into_inner(mut self) -> T {
        // Safety: we read before zeroing so the caller still gets the value.
        // The zero is then written to the (soon-to-be-dropped) stack slot to
        // prevent the value leaking via uninitialized memory patterns.
        let val = self.inner;
        self.zero();
        // Prevent the Drop impl from zeroing again after we zeroed here.
        mem::forget(self);
        val
    }

    /// Explicitly zeroes the buffer.  Called automatically by `Drop`; can also
    /// be called manually for eager wiping.
    #[inline(always)]
    pub fn zero(&mut self) {
        // SAFETY: `self.inner` is a valid, properly-aligned value of type `T`
        // and `size_of::<T>()` is the correct byte count.  `write_volatile`
        // through a `*mut u8` pointer performs a byte-by-byte write that the
        // compiler must emit (the volatile qualifier forbids elision).
        unsafe {
            let ptr = &mut self.inner as *mut T as *mut u8;
            let len = mem::size_of::<T>();
            for i in 0..len {
                ptr::write_volatile(ptr.add(i), 0u8);
            }
        }
    }
}

impl<T: Copy> Drop for SensitiveBuffer<T> {
    #[inline(always)]
    fn drop(&mut self) {
        self.zero();
    }
}

/// A heap-backed (alloc) vector of `T` where every element is zeroed before
/// the allocation is released.  Available only when the `alloc` crate is in
/// scope (which it always is in `soroban-zk-std` via `extern crate alloc`).
///
/// This is the correct type to use for the deserialized `public_inputs` slice
/// during proof verification, since the number of inputs is not known at
/// compile time.
#[cfg(feature = "alloc")]
pub use self::sensitive_vec::SensitiveVec;

// SensitiveVec is also used from soroban-zk-std where alloc is always present.
// We expose the module unconditionally and let callers opt in.
pub mod sensitive_vec {
    extern crate alloc;
    use alloc::vec::Vec;
    use core::mem;
    use core::ptr;

    /// A RAII guard over a `Vec<T>` that zeroes every element (byte-by-byte,
    /// volatile) before releasing the allocation on `Drop`.
    pub struct SensitiveVec<T: Copy> {
        inner: Vec<T>,
    }

    impl<T: Copy> SensitiveVec<T> {
        /// Wraps an existing `Vec<T>`.
        #[inline(always)]
        pub fn new(v: Vec<T>) -> Self {
            Self { inner: v }
        }

        /// Returns a shared slice of the wrapped values.
        #[inline(always)]
        pub fn as_slice(&self) -> &[T] {
            &self.inner
        }
    }

    impl<T: Copy> Drop for SensitiveVec<T> {
        fn drop(&mut self) {
            // SAFETY: every element of `self.inner` is a valid `T`; we write
            // through a byte pointer using volatile semantics to prevent
            // dead-store elimination, then let Vec's own drop release the heap.
            unsafe {
                let ptr = self.inner.as_mut_ptr() as *mut u8;
                let len = self.inner.len() * mem::size_of::<T>();
                for i in 0..len {
                    ptr::write_volatile(ptr.add(i), 0u8);
                }
            }
            // Vec<T>::drop now runs and frees the (already-zeroed) allocation.
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensitive_buffer_zeroes_on_drop() {
        // Use a u64 with a known sentinel value.
        let leaked_ptr: *const u64;
        {
            let buf = SensitiveBuffer::new(0xDEAD_BEEF_CAFE_BABEu64);
            leaked_ptr = buf.as_ref() as *const u64;
            assert_eq!(*buf.as_ref(), 0xDEAD_BEEF_CAFE_BABEu64);
            // buf is dropped here; zero-fill runs.
        }
        // SAFETY: the stack frame is still accessible immediately after `buf`
        // is dropped — on most platforms the frame is not reclaimed until the
        // surrounding function returns — allowing us to observe the wipe.
        // This is inherently platform-specific; the test is a best-effort
        // smoke-test of the volatile write, not a formal security proof.
        let after_drop = unsafe { core::ptr::read_volatile(leaked_ptr) };
        assert_eq!(after_drop, 0u64, "volatile zero-fill must have run");
    }

    #[test]
    fn sensitive_buffer_as_mut_reflects_update() {
        let mut buf = SensitiveBuffer::new(1u32);
        *buf.as_mut() = 99u32;
        assert_eq!(*buf.as_ref(), 99u32);
    }

    #[test]
    fn sensitive_buffer_into_inner_returns_value() {
        let buf = SensitiveBuffer::new(42u128);
        assert_eq!(buf.into_inner(), 42u128);
    }

    #[test]
    fn sensitive_buffer_explicit_zero() {
        let mut buf = SensitiveBuffer::new(0xFFu8);
        buf.zero();
        assert_eq!(*buf.as_ref(), 0u8);
    }

    #[test]
    fn sensitive_vec_zeroes_on_drop() {
        use sensitive_vec::SensitiveVec;
        extern crate alloc;
        use alloc::vec;

        let v: alloc::vec::Vec<u32> = vec![0xDEAD_BEEFu32; 4];
        let raw_ptr = v.as_ptr();
        let _guard = SensitiveVec::new(v);
        // The guard is dropped at the end of this scope.
        drop(_guard);
        // Read the now-freed backing store through the stale pointer.
        // SAFETY: The allocator has not yet reclaimed this memory on any
        // mainstream target; the volatile write should already have zeroed it.
        // This is a best-effort smoke-test.
        let after = unsafe { core::ptr::read_volatile(raw_ptr) };
        assert_eq!(after, 0u32, "SensitiveVec must zero elements before freeing");
    }
}
