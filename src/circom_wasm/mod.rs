mod wasm;
pub use wasm::WitnessCalculator;

mod memory;
pub use memory::SafeMemory;

mod circom;
pub use circom::CircomInstance;

use fnv::FnvHasher;
use std::hash::Hasher;

pub use num_bigint::BigInt;

pub(crate) fn fnv(inp: &str) -> (u32, u32) {
    let mut hasher = FnvHasher::default();
    hasher.write(inp.as_bytes());
    let h = hasher.finish();

    ((h >> 32) as u32, h as u32)
}
