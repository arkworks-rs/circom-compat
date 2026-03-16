use num_bigint::BigInt;
use std::io::{self, Write};

/// Writes a witness in the snarkjs-compatible `.wtns` binary format.
///
/// The `.wtns` format uses the iden3 binary container with two sections:
/// - Section 1 (header): field element byte size, prime, and witness count
/// - Section 2 (data): witness values as little-endian field elements
pub fn write_wtns<W: Write>(writer: &mut W, witness: &[BigInt], prime: &BigInt) -> io::Result<()> {
    let n8 = ((prime.bits() as usize - 1) / 64 + 1) * 8;
    let n_witness = witness.len() as u32;

    // Global header
    writer.write_all(b"wtns")?;
    writer.write_all(&2u32.to_le_bytes())?;
    writer.write_all(&2u32.to_le_bytes())?;

    // Section 1: Header
    let section1_size = (4 + n8 + 4) as u64;
    writer.write_all(&1u32.to_le_bytes())?;
    writer.write_all(&section1_size.to_le_bytes())?;
    writer.write_all(&(n8 as u32).to_le_bytes())?;
    write_bigint_le(writer, prime, n8)?;
    writer.write_all(&n_witness.to_le_bytes())?;

    // Section 2: Witness data
    let section2_size = (n8 as u64) * (n_witness as u64);
    writer.write_all(&2u32.to_le_bytes())?;
    writer.write_all(&section2_size.to_le_bytes())?;
    for w in witness {
        write_bigint_le(writer, w, n8)?;
    }

    Ok(())
}

fn write_bigint_le<W: Write>(writer: &mut W, value: &BigInt, n8: usize) -> io::Result<()> {
    let (_, bytes) = value.to_bytes_le();
    let len = bytes.len().min(n8);
    writer.write_all(&bytes[..len])?;
    // Zero-pad to n8
    let padding = n8 - len;
    if padding > 0 {
        writer.write_all(&vec![0u8; padding])?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn bn254_prime() -> BigInt {
        BigInt::from_str(
            "21888242871839275222246405745257275088548364400416034343698204186575808495617",
        )
        .unwrap()
    }

    #[test]
    fn wtns_header_structure() {
        let prime = bn254_prime();
        let witness = vec![
            BigInt::from(1),
            BigInt::from(33),
            BigInt::from(3),
            BigInt::from(11),
        ];

        let mut buf = Vec::new();
        write_wtns(&mut buf, &witness, &prime).unwrap();

        // Magic
        assert_eq!(&buf[0..4], b"wtns");
        // Version
        assert_eq!(u32::from_le_bytes(buf[4..8].try_into().unwrap()), 2);
        // Num sections
        assert_eq!(u32::from_le_bytes(buf[8..12].try_into().unwrap()), 2);
        // Section 1 type
        assert_eq!(u32::from_le_bytes(buf[12..16].try_into().unwrap()), 1);
        // Section 1 size: 4 + 32 + 4 = 40
        assert_eq!(u64::from_le_bytes(buf[16..24].try_into().unwrap()), 40);
        // n8
        assert_eq!(u32::from_le_bytes(buf[24..28].try_into().unwrap()), 32);
        // nWitness (at offset 24 + 4 + 32 = 60)
        assert_eq!(u32::from_le_bytes(buf[60..64].try_into().unwrap()), 4);
        // Section 2 type
        assert_eq!(u32::from_le_bytes(buf[64..68].try_into().unwrap()), 2);
        // Section 2 size: 32 * 4 = 128
        assert_eq!(u64::from_le_bytes(buf[68..76].try_into().unwrap()), 128);

        // Total size: 12 + 12 + 40 + 12 + 128 = 204
        assert_eq!(buf.len(), 204);
    }

    #[test]
    fn wtns_witness_values() {
        let prime = bn254_prime();
        let witness = vec![
            BigInt::from(1),
            BigInt::from(33),
            BigInt::from(3),
            BigInt::from(11),
        ];

        let mut buf = Vec::new();
        write_wtns(&mut buf, &witness, &prime).unwrap();

        let data_offset = 76; // after all headers
        let n8 = 32;

        // Witness[0] = 1 → 0x01 LE
        assert_eq!(buf[data_offset], 0x01);
        assert!(
            buf[data_offset + 1..data_offset + n8]
                .iter()
                .all(|&b| b == 0)
        );

        // Witness[1] = 33 → 0x21 LE
        assert_eq!(buf[data_offset + n8], 0x21);
        assert!(
            buf[data_offset + n8 + 1..data_offset + 2 * n8]
                .iter()
                .all(|&b| b == 0)
        );

        // Witness[2] = 3 → 0x03 LE
        assert_eq!(buf[data_offset + 2 * n8], 0x03);

        // Witness[3] = 11 → 0x0B LE
        assert_eq!(buf[data_offset + 3 * n8], 0x0B);
    }

    #[test]
    fn wtns_prime_encoding() {
        let prime = bn254_prime();
        let witness = vec![BigInt::from(1)];

        let mut buf = Vec::new();
        write_wtns(&mut buf, &witness, &prime).unwrap();

        // Prime starts at offset 28, 32 bytes LE
        let prime_bytes = &buf[28..60];
        // BN254 prime in LE: starts with 0x01 0x00 0x00 0xF0...
        assert_eq!(prime_bytes[0], 0x01);
        assert_eq!(prime_bytes[1], 0x00);
        assert_eq!(prime_bytes[2], 0x00);
        assert_eq!(prime_bytes[3], 0xF0);
        // ...ends with 0x30
        assert_eq!(prime_bytes[31], 0x30);
    }

    #[test]
    fn wtns_empty_witness() {
        let prime = bn254_prime();
        let witness: Vec<BigInt> = vec![];

        let mut buf = Vec::new();
        write_wtns(&mut buf, &witness, &prime).unwrap();

        // Total: 12 + 12 + 40 + 12 + 0 = 76
        assert_eq!(buf.len(), 76);
        assert_eq!(u32::from_le_bytes(buf[60..64].try_into().unwrap()), 0);
        assert_eq!(u64::from_le_bytes(buf[68..76].try_into().unwrap()), 0);
    }
}
