//! Safe-ish interface for reading and writing specific types to the WASM runtime's memory
use ark_serialize::CanonicalDeserialize;
use num_traits::ToPrimitive;
use wasmer::{Memory, MemoryAccessError, MemoryView, Store};

// TODO: Decide whether we want Ark here or if it should use a generic BigInt package
use ark_bn254::FrConfig;
use ark_ff::MontConfig;
use ark_ff::{BigInteger, BigInteger256, Zero};

use num_bigint::{BigInt, BigUint};

use color_eyre::Result;
use std::io::Cursor;
use std::str::FromStr;
use std::{convert::TryFrom, ops::Deref};

#[derive(Debug)]
pub struct SafeMemory {
    pub memory: Memory,
    pub prime: BigInt,

    short_max: BigInt,
    short_min: BigInt,
    r_inv: BigInt,
    n32: usize,
}

impl Deref for SafeMemory {
    type Target = Memory;

    fn deref(&self) -> &Self::Target {
        &self.memory
    }
}

impl SafeMemory {
    /// Creates a new SafeMemory
    pub fn new(memory: Memory, n32: usize, prime: BigInt) -> Self {
        // TODO: Figure out a better way to calculate these
        let short_max = BigInt::from(0x8000_0000u64);
        let short_min =
            BigInt::from_biguint(num_bigint::Sign::NoSign, BigUint::from(FrConfig::MODULUS))
                - &short_max;
        let r_inv = BigInt::from_str(
            "9915499612839321149637521777990102151350674507940716049588462388200839649614",
        )
        .unwrap();

        Self {
            memory,
            prime,

            short_max,
            short_min,
            r_inv,
            n32,
        }
    }

    /// Gets an immutable view to the memory in 32 byte chunks
    pub fn view<'a>(&self, store: &'a mut Store) -> MemoryView<'a> {
        self.memory.view(store)
    }

    /// Returns the next free position in the memory
    pub fn free_pos(&self, store: &mut Store) -> Result<u32, MemoryAccessError> {
        self.read_u32(store, 0)
    }

    /// Sets the next free position in the memory
    pub fn set_free_pos(&self, store: &mut Store, ptr: u32) -> Result<(), MemoryAccessError> {
        self.write_u32(store, 0, ptr)
    }

    /// Allocates a U32 in memory
    pub fn alloc_u32(&self, store: &mut Store) -> Result<u32, MemoryAccessError> {
        let p = self.free_pos(store)?;
        self.set_free_pos(store, p + 8)?;
        Ok(p)
    }

    /// Writes a u32 to the specified memory offset
    pub fn write_u32(
        &self,
        store: &mut Store,
        ptr: usize,
        num: u32,
    ) -> Result<(), MemoryAccessError> {
        let bytes = num.to_le_bytes();
        self.view(store).write(ptr as u64, &bytes)
    }

    /// Reads a u32 from the specified memory offset
    pub fn read_u32(&self, store: &mut Store, ptr: usize) -> Result<u32, MemoryAccessError> {
        let mut bytes = [0; 4];
        self.view(store).read(ptr as u64, &mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    pub fn read_byte(&self, store: &mut Store, ptr: usize) -> Result<u8, MemoryAccessError> {
        let mut bytes = [0; 1];
        self.view(store).read(ptr as u64, &mut bytes)?;
        Ok(u8::from_le_bytes(bytes))
    }

    /// Allocates `self.n32 * 4 + 8` bytes in the memory
    pub fn alloc_fr(&self, store: &mut Store) -> Result<u32, MemoryAccessError> {
        let p = self.free_pos(store)?;
        self.set_free_pos(store, p + self.n32 as u32 * 4 + 8)?;
        Ok(p)
    }

    /// Writes a Field Element to memory at the specified offset, truncating
    /// to smaller u32 types if needed and adjusting the sign via 2s complement
    pub fn write_fr(&self, store: &mut Store, ptr: usize, fr: &BigInt) -> Result<()> {
        if fr < &self.short_max && fr > &self.short_min {
            if fr >= &BigInt::zero() {
                self.write_short_positive(store, ptr, fr)?;
            } else {
                self.write_short_negative(store, ptr, fr)?;
            }
        } else {
            self.write_long_normal(store, ptr, fr)?;
        }

        Ok(())
    }

    /// Reads a Field Element from the memory at the specified offset
    pub fn read_fr(&self, store: &mut Store, ptr: usize) -> Result<BigInt, MemoryAccessError> {
        let test_byte = self.read_byte(store, ptr + 4 + 3)?;
        let test_byte2 = self.read_byte(store, ptr + 3)?;

        if test_byte & 0x80 != 0 {
            let mut num = self.read_big(store, ptr + 8, self.n32)?;
            if test_byte & 0x40 != 0 {
                num = (num * &self.r_inv) % &self.prime
            }
            Ok(num)
        } else if test_byte2 & 0x40 != 0 {
            let mut num = self.read_u32(store, ptr).map(|x| x.into())?;
            // handle small negative
            num -= BigInt::from(0x100000000i64);
            Ok(num)
        } else {
            self.read_u32(store, ptr).map(|x| x.into())
        }
    }

    fn write_short_positive(&self, store: &mut Store, ptr: usize, fr: &BigInt) -> Result<()> {
        let num = fr.to_i32().expect("not a short positive");
        self.write_u32(store, ptr, num as u32)?;
        self.write_u32(store, ptr + 4, 0)?;
        Ok(())
    }

    fn write_short_negative(&self, store: &mut Store, ptr: usize, fr: &BigInt) -> Result<()> {
        // 2s complement
        let num = fr - &self.short_min;
        let num = num - &self.short_max;
        let num = num + BigInt::from(0x0001_0000_0000i64);

        let num = num
            .to_u32()
            .expect("could not cast as u32 (should never happen)");

        self.write_u32(store, ptr, num)?;
        self.write_u32(store, ptr + 4, 0)?;
        Ok(())
    }

    fn write_long_normal(&self, store: &mut Store, ptr: usize, fr: &BigInt) -> Result<()> {
        self.write_u32(store, ptr, 0)?;
        self.write_u32(store, ptr + 4, i32::MIN as u32)?; // 0x80000000
        self.write_big(store, ptr + 8, fr)?;
        Ok(())
    }

    fn write_big(
        &self,
        store: &mut Store,
        ptr: usize,
        num: &BigInt,
    ) -> Result<(), MemoryAccessError> {
        let (_, num) = num.clone().into_parts();
        let num = BigInteger256::try_from(num).unwrap();

        let bytes = num.to_bytes_le();
        self.view(store).write(ptr as u64, &bytes)
    }

    /// Reads `num_bytes * 32` from the specified memory offset in a Big Integer
    pub fn read_big(
        &self,
        store: &mut Store,
        ptr: usize,
        num_bytes: usize,
    ) -> Result<BigInt, MemoryAccessError> {
        let mut buf = vec![0; num_bytes * 32];
        self.view(store).read(ptr as u64, &mut buf)?;
        // TODO: Is there a better way to read big integers?
        let big = BigInteger256::deserialize_uncompressed(&mut Cursor::new(buf)).unwrap();
        let big = BigUint::from(big);
        Ok(big.into())
    }
}

// TODO: Figure out how to read / write numbers > u32
// circom-witness-calculator: Wasm + Memory -> expose BigInts so that they can be consumed by any proof system
// ark-circom:
// 1. can read zkey
// 2. can generate witness from inputs
// 3. can generate proofs
// 4. can serialize proofs in the desired format
#[cfg(test)]
mod tests {
    use super::*;
    use num_traits::ToPrimitive;
    use std::str::FromStr;
    use wasmer::{MemoryType, Store};

    fn new() -> (SafeMemory, Store) {
        let mut store = Store::default();
        let mem = SafeMemory::new(
            Memory::new(&mut store, MemoryType::new(1, None, false)).unwrap(),
            2,
            BigInt::from_str(
                "21888242871839275222246405745257275088548364400416034343698204186575808495617",
            )
            .unwrap(),
        );
        (mem, store)
    }

    #[test]
    fn i32_bounds() {
        let (mem, _) = new();
        let i32_max = i32::MAX as i64 + 1;
        assert_eq!(mem.short_min.to_i64().unwrap(), -i32_max);
        assert_eq!(mem.short_max.to_i64().unwrap(), i32_max);
    }

    #[test]
    fn read_write_32() {
        let (mem, mut store) = new();
        let num = u32::MAX;

        let inp = mem.read_u32(&mut store, 0).unwrap();
        assert_eq!(inp, 0);

        mem.write_u32(&mut store, 0, num).unwrap();
        let inp = mem.read_u32(&mut store, 0).unwrap();
        assert_eq!(inp, num);
    }

    #[test]
    fn read_write_fr_small_positive() {
        read_write_fr(BigInt::from(1_000_000));
    }

    #[test]
    fn read_write_fr_small_negative() {
        read_write_fr(BigInt::from(-1_000_000));
    }

    #[test]
    fn read_write_fr_big_positive() {
        read_write_fr(BigInt::from(500000000000i64));
    }

    // TODO: How should this be handled?
    #[test]
    #[ignore]
    fn read_write_fr_big_negative() {
        read_write_fr(BigInt::from_str("-500000000000").unwrap())
    }

    fn read_write_fr(num: BigInt) {
        let (mem, mut store) = new();
        mem.write_fr(&mut store, 0, &num).unwrap();
        let res = mem.read_fr(&mut store, 0).unwrap();
        assert_eq!(res, num);
    }
}
