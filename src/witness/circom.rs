use color_eyre::Result;
use wasmer::{Exports, Function, Store, Value};

#[derive(Debug)]
pub struct Wasm {
    pub exports: Exports,
}

pub trait CircomBase {
    fn init(&self, store: &mut Store, sanity_check: bool) -> Result<()>;
    fn func(&self, name: &str) -> &Function;
    fn get_n_vars(&self, store: &mut Store) -> Result<u32>;
    fn get_u32(&self, store: &mut Store, name: &str) -> Result<u32>;
    // Only exists natively in Circom2, hardcoded for Circom
    fn get_version(&self, store: &mut Store) -> Result<u32>;
}

pub trait Circom1 {
    fn get_ptr_witness(&self, store: &mut Store, w: u32) -> Result<u32>;
    fn get_fr_len(&self, store: &mut Store) -> Result<u32>;
    fn get_signal_offset32(
        &self,
        store: &mut Store,
        p_sig_offset: u32,
        component: u32,
        hash_msb: u32,
        hash_lsb: u32,
    ) -> Result<()>;
    fn set_signal(
        &self,
        store: &mut Store,
        c_idx: u32,
        component: u32,
        signal: u32,
        p_val: u32,
    ) -> Result<()>;
    fn get_ptr_raw_prime(&self, store: &mut Store) -> Result<u32>;
}

pub trait Circom2 {
    fn get_field_num_len32(&self, store: &mut Store) -> Result<u32>;
    fn get_raw_prime(&self, store: &mut Store) -> Result<()>;
    fn read_shared_rw_memory(&self, store: &mut Store, i: u32) -> Result<u32>;
    fn write_shared_rw_memory(&self, store: &mut Store, i: u32, v: u32) -> Result<()>;
    fn set_input_signal(&self, store: &mut Store, hmsb: u32, hlsb: u32, pos: u32) -> Result<()>;
    fn get_witness(&self, store: &mut Store, i: u32) -> Result<()>;
    fn get_witness_size(&self, store: &mut Store) -> Result<u32>;
}

impl Circom1 for Wasm {
    fn get_fr_len(&self, store: &mut Store) -> Result<u32> {
        self.get_u32(store, "getFrLen")
    }

    fn get_ptr_raw_prime(&self, store: &mut Store) -> Result<u32> {
        self.get_u32(store, "getPRawPrime")
    }

    fn get_ptr_witness(&self, store: &mut Store, w: u32) -> Result<u32> {
        let func = self.func("getPWitness");

        let res = func.call(store, &[w.into()])?;

        Ok(res[0].unwrap_i32() as u32)
    }

    fn get_signal_offset32(
        &self,
        store: &mut Store,
        p_sig_offset: u32,
        component: u32,
        hash_msb: u32,
        hash_lsb: u32,
    ) -> Result<()> {
        let func = self.func("getSignalOffset32");
        func.call(
            store,
            &[
                p_sig_offset.into(),
                component.into(),
                hash_msb.into(),
                hash_lsb.into(),
            ],
        )?;

        Ok(())
    }

    fn set_signal(
        &self,
        store: &mut Store,
        c_idx: u32,
        component: u32,
        signal: u32,
        p_val: u32,
    ) -> Result<()> {
        let func = self.func("setSignal");
        func.call(
            store,
            &[c_idx.into(), component.into(), signal.into(), p_val.into()],
        )?;

        Ok(())
    }
}

#[cfg(feature = "circom-2")]
impl Circom2 for Wasm {
    fn get_field_num_len32(&self, store: &mut Store) -> Result<u32> {
        self.get_u32(store, "getFieldNumLen32")
    }

    fn get_raw_prime(&self, store: &mut Store) -> Result<()> {
        let func = self.func("getRawPrime");
        func.call(store, &[])?;
        Ok(())
    }

    fn read_shared_rw_memory(&self, store: &mut Store, i: u32) -> Result<u32> {
        let func = self.func("readSharedRWMemory");
        let result = func.call(store, &[i.into()])?;
        Ok(result[0].unwrap_i32() as u32)
    }

    fn write_shared_rw_memory(&self, store: &mut Store, i: u32, v: u32) -> Result<()> {
        let func = self.func("writeSharedRWMemory");
        func.call(store, &[i.into(), v.into()])?;
        Ok(())
    }

    fn set_input_signal(&self, store: &mut Store, hmsb: u32, hlsb: u32, pos: u32) -> Result<()> {
        let func = self.func("setInputSignal");
        func.call(store, &[hmsb.into(), hlsb.into(), pos.into()])?;
        Ok(())
    }

    fn get_witness(&self, store: &mut Store, i: u32) -> Result<()> {
        let func = self.func("getWitness");
        func.call(store, &[i.into()])?;
        Ok(())
    }

    fn get_witness_size(&self, store: &mut Store) -> Result<u32> {
        self.get_u32(store, "getWitnessSize")
    }
}

impl CircomBase for Wasm {
    fn init(&self, store: &mut Store, sanity_check: bool) -> Result<()> {
        let func = self.func("init");
        func.call(store, &[Value::I32(sanity_check as i32)])?;
        Ok(())
    }

    fn get_n_vars(&self, store: &mut Store) -> Result<u32> {
        self.get_u32(store, "getNVars")
    }

    // Default to version 1 if it isn't explicitly defined
    fn get_version(&self, store: &mut Store) -> Result<u32> {
        match self.exports.get_function("getVersion") {
            Ok(func) => Ok(func.call(store, &[])?[0].unwrap_i32() as u32),
            Err(_) => Ok(1),
        }
    }

    fn get_u32(&self, store: &mut Store, name: &str) -> Result<u32> {
        let func = &self.func(name);
        let result = func.call(store, &[])?;
        Ok(result[0].unwrap_i32() as u32)
    }

    fn func(&self, name: &str) -> &Function {
        self.exports
            .get_function(name)
            .unwrap_or_else(|_| panic!("function {} not found", name))
    }
}

impl Wasm {
    pub fn new(exports: Exports) -> Self {
        Self { exports }
    }
}
