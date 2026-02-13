//! Unsafe code metrics tracking
//!
//! Aggregates counts of all unsafe patterns found across the program.

use serde::{Deserialize, Serialize};

/// Aggregated metrics for unsafe code across the program
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsafeMetrics {
    /// Total `unsafe {}` blocks
    pub unsafe_blocks: usize,
    /// Total `unsafe fn` declarations
    pub unsafe_functions: usize,
    /// Total `extern "C" fn` and FFI calls
    pub ffi_calls: usize,
    /// Total raw pointer usage (*const T, *mut T)
    pub raw_pointers: usize,
    /// Total `std::mem::transmute` calls
    pub transmute_calls: usize,
    /// Total inline assembly blocks (asm!, global_asm!)
    pub asm_blocks: usize,
    /// Total `unsafe impl` blocks
    pub unsafe_traits: usize,
    /// Total union type declarations
    pub union_types: usize,
}

impl UnsafeMetrics {
    pub fn new() -> Self {
        Self {
            unsafe_blocks: 0,
            unsafe_functions: 0,
            ffi_calls: 0,
            raw_pointers: 0,
            transmute_calls: 0,
            asm_blocks: 0,
            unsafe_traits: 0,
            union_types: 0,
        }
    }

    /// Total unsafe patterns found
    pub fn total_unsafe(&self) -> usize {
        self.unsafe_blocks
            + self.unsafe_functions
            + self.ffi_calls
            + self.raw_pointers
            + self.transmute_calls
            + self.asm_blocks
            + self.unsafe_traits
            + self.union_types
    }

    /// Returns a summary string for logging
    pub fn summary(&self) -> String {
        format!(
            "unsafe_blocks={}, unsafe_fns={}, ffi={}, raw_ptrs={}, transmute={}, asm={}, unsafe_traits={}, unions={}",
            self.unsafe_blocks, self.unsafe_functions, self.ffi_calls,
            self.raw_pointers, self.transmute_calls, self.asm_blocks,
            self.unsafe_traits, self.union_types
        )
    }
}

impl Default for UnsafeMetrics {
    fn default() -> Self {
        Self::new()
    }
}
