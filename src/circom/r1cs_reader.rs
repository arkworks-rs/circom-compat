//! R1CS circom file reader
//! Copied from <https://github.com/poma/zkutil>
//! Spec: <https://github.com/iden3/r1csfile/blob/master/doc/r1cs_bin_format.md>
use byteorder::{LittleEndian, ReadBytesExt};
use std::io::{Error, ErrorKind, Result};

use ark_ec::PairingEngine;
use ark_ff::FromBytes;
use ark_std::io::{Read, Seek, SeekFrom};

use std::collections::HashMap;

use super::{ConstraintVec, Constraints};

#[derive(Clone, Debug)]
pub struct R1CS<E: PairingEngine> {
    pub num_inputs: usize,
    pub num_aux: usize,
    pub num_variables: usize,
    pub constraints: Vec<Constraints<E>>,
    pub wire_mapping: Option<Vec<usize>>,
}

impl<E: PairingEngine> From<R1CSFile<E>> for R1CS<E> {
    fn from(file: R1CSFile<E>) -> Self {
        let num_inputs = (1 + file.header.n_pub_in + file.header.n_pub_out) as usize;
        let num_variables = file.header.n_wires as usize;
        let num_aux = num_variables - num_inputs;
        R1CS {
            num_aux,
            num_inputs,
            num_variables,
            constraints: file.constraints,
            wire_mapping: Some(file.wire_mapping.iter().map(|e| *e as usize).collect()),
        }
    }
}

pub struct R1CSFile<E: PairingEngine> {
    pub version: u32,
    pub header: Header,
    pub constraints: Vec<Constraints<E>>,
    pub wire_mapping: Vec<u64>,
}

impl<E: PairingEngine> R1CSFile<E> {
    /// reader must implement the Seek trait, for example with a Cursor
    ///
    /// ```rust,ignore
    /// let reader = BufReader::new(Cursor::new(&data[..]));
    /// ```
    pub fn new<R: Read + Seek>(mut reader: R) -> Result<R1CSFile<E>> {
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;
        if magic != [0x72, 0x31, 0x63, 0x73] {
            // magic = "r1cs"
            return Err(Error::new(ErrorKind::InvalidData, "Invalid magic number"));
        }

        let version = reader.read_u32::<LittleEndian>()?;
        if version != 1 {
            return Err(Error::new(ErrorKind::InvalidData, "Unsupported version"));
        }

        let num_sections = reader.read_u32::<LittleEndian>()?;

        // todo: handle sec_size correctly
        // section type -> file offset
        let mut sec_offsets = HashMap::<u32, u64>::new();
        let mut sec_sizes = HashMap::<u32, u64>::new();

        // get file offset of each section
        for _ in 0..num_sections {
            let sec_type = reader.read_u32::<LittleEndian>()?;
            let sec_size = reader.read_u64::<LittleEndian>()?;
            let offset = reader.stream_position()?;
            sec_offsets.insert(sec_type, offset);
            sec_sizes.insert(sec_type, sec_size);
            reader.seek(SeekFrom::Current(sec_size as i64))?;
        }

        let header_type = 1;
        let constraint_type = 2;
        let wire2label_type = 3;

        let header_offset = sec_offsets.get(&header_type).ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidData,
                "No section offset for header type found",
            )
        });

        reader.seek(SeekFrom::Start(*header_offset?))?;

        let header_size = sec_sizes.get(&header_type).ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidData,
                "No section size for header type found",
            )
        });

        let header = Header::new(&mut reader, *header_size?)?;

        let constraint_offset = sec_offsets.get(&constraint_type).ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidData,
                "No section offset for constraint type found",
            )
        });

        reader.seek(SeekFrom::Start(*constraint_offset?))?;

        let constraints = read_constraints::<&mut R, E>(&mut reader, &header)?;

        let wire2label_offset = sec_offsets.get(&wire2label_type).ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidData,
                "No section offset for wire2label type found",
            )
        });

        reader.seek(SeekFrom::Start(*wire2label_offset?))?;

        let wire2label_size = sec_sizes.get(&wire2label_type).ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidData,
                "No section size for wire2label type found",
            )
        });

        let wire_mapping = read_map(&mut reader, *wire2label_size?, &header)?;

        Ok(R1CSFile {
            version,
            header,
            constraints,
            wire_mapping,
        })
    }
}

pub struct Header {
    pub field_size: u32,
    pub prime_size: Vec<u8>,
    pub n_wires: u32,
    pub n_pub_out: u32,
    pub n_pub_in: u32,
    pub n_prv_in: u32,
    pub n_labels: u64,
    pub n_constraints: u32,
}

impl Header {
    fn new<R: Read>(mut reader: R, size: u64) -> Result<Header> {
        let field_size = reader.read_u32::<LittleEndian>()?;
        if field_size != 32 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "This parser only supports 32-byte fields",
            ));
        }

        if size != 32 + field_size as u64 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Invalid header section size",
            ));
        }

        let mut prime_size = vec![0u8; field_size as usize];
        reader.read_exact(&mut prime_size)?;

        if prime_size
            != hex::decode("010000f093f5e1439170b97948e833285d588181b64550b829a031e1724e6430")
                .unwrap()
        {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "This parser only supports bn256",
            ));
        }

        Ok(Header {
            field_size,
            prime_size,
            n_wires: reader.read_u32::<LittleEndian>()?,
            n_pub_out: reader.read_u32::<LittleEndian>()?,
            n_pub_in: reader.read_u32::<LittleEndian>()?,
            n_prv_in: reader.read_u32::<LittleEndian>()?,
            n_labels: reader.read_u64::<LittleEndian>()?,
            n_constraints: reader.read_u32::<LittleEndian>()?,
        })
    }
}

fn read_constraint_vec<R: Read, E: PairingEngine>(mut reader: R) -> Result<ConstraintVec<E>> {
    let n_vec = reader.read_u32::<LittleEndian>()? as usize;
    let mut vec = Vec::with_capacity(n_vec);
    for _ in 0..n_vec {
        vec.push((
            reader.read_u32::<LittleEndian>()? as usize,
            E::Fr::read(&mut reader)?,
        ));
    }
    Ok(vec)
}

fn read_constraints<R: Read, E: PairingEngine>(
    mut reader: R,
    header: &Header,
) -> Result<Vec<Constraints<E>>> {
    // todo check section size
    let mut vec = Vec::with_capacity(header.n_constraints as usize);
    for _ in 0..header.n_constraints {
        vec.push((
            read_constraint_vec::<&mut R, E>(&mut reader)?,
            read_constraint_vec::<&mut R, E>(&mut reader)?,
            read_constraint_vec::<&mut R, E>(&mut reader)?,
        ));
    }
    Ok(vec)
}

fn read_map<R: Read>(mut reader: R, size: u64, header: &Header) -> Result<Vec<u64>> {
    if size != header.n_wires as u64 * 8 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "Invalid map section size",
        ));
    }
    let mut vec = Vec::with_capacity(header.n_wires as usize);
    for _ in 0..header.n_wires {
        vec.push(reader.read_u64::<LittleEndian>()?);
    }
    if vec[0] != 0 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "Wire 0 should always be mapped to 0",
        ));
    }
    Ok(vec)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{Bn254, Fr};
    use ark_std::io::{BufReader, Cursor};

    #[test]
    fn sample() {
        let data = hex_literal::hex!(
            "
        72316373
        01000000
        03000000
        01000000 40000000 00000000
        20000000
        010000f0 93f5e143 9170b979 48e83328 5d588181 b64550b8 29a031e1 724e6430
        07000000
        01000000
        02000000
        03000000
        e8030000 00000000
        03000000
        02000000 88020000 00000000
        02000000
        05000000 03000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        06000000 08000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        03000000
        00000000 02000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        02000000 14000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        03000000 0C000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        02000000
        00000000 05000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        02000000 07000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        03000000
        01000000 04000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        04000000 08000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        05000000 03000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        02000000
        03000000 2C000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        06000000 06000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        00000000
        01000000
        06000000 04000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        03000000
        00000000 06000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        02000000 0B000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        03000000 05000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        01000000
        06000000 58020000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        03000000 38000000 00000000
        00000000 00000000
        03000000 00000000
        0a000000 00000000
        0b000000 00000000
        0c000000 00000000
        0f000000 00000000
        44010000 00000000
    "
        );

        let reader = BufReader::new(Cursor::new(&data[..]));
        let file = R1CSFile::<Bn254>::new(reader).unwrap();
        assert_eq!(file.version, 1);

        assert_eq!(file.header.field_size, 32);
        assert_eq!(
            file.header.prime_size,
            hex::decode("010000f093f5e1439170b97948e833285d588181b64550b829a031e1724e6430")
                .unwrap(),
        );
        assert_eq!(file.header.n_wires, 7);
        assert_eq!(file.header.n_pub_out, 1);
        assert_eq!(file.header.n_pub_in, 2);
        assert_eq!(file.header.n_prv_in, 3);
        assert_eq!(file.header.n_labels, 0x03e8);
        assert_eq!(file.header.n_constraints, 3);

        assert_eq!(file.constraints.len(), 3);
        assert_eq!(file.constraints[0].0.len(), 2);
        assert_eq!(file.constraints[0].0[0].0, 5);
        assert_eq!(file.constraints[0].0[0].1, Fr::from(3));
        assert_eq!(file.constraints[2].1[0].0, 0);
        assert_eq!(file.constraints[2].1[0].1, Fr::from(6));
        assert_eq!(file.constraints[1].2.len(), 0);

        assert_eq!(file.wire_mapping.len(), 7);
        assert_eq!(file.wire_mapping[1], 3);
    }
}
