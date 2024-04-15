use color_eyre::Result;
use wasmer::{Function, Instance, Store, Value};

#[derive(Debug)]
pub struct Wasm {
    instance: Instance,
    store: Store,
}

pub trait CircomBase {
    fn init(&mut self, sanity_check: bool) -> Result<()>;
    fn func(&self, name: &str) -> &Function;
    fn get_n_vars(&self) -> Result<u32>;
    fn get_u32(&mut self, name: &str) -> Result<u32>;
    // Only exists natively in Circom2, hardcoded for Circom
    fn get_version(&mut self) -> Result<u32>;
}

pub trait Circom1 {
    fn get_ptr_witness(&mut self, w: u32) -> Result<u32>;
    fn get_fr_len(&self) -> Result<u32>;
    fn get_signal_offset32(
        &mut self,
        p_sig_offset: u32,
        component: u32,
        hash_msb: u32,
        hash_lsb: u32,
    ) -> Result<()>;
    fn set_signal(&mut self, c_idx: u32, component: u32, signal: u32, p_val: u32) -> Result<()>;
    fn get_ptr_raw_prime(&self) -> Result<u32>;
}

pub trait Circom2 {
    fn get_field_num_len32(&self) -> Result<u32>;
    fn get_raw_prime(&mut self) -> Result<()>;
    fn read_shared_rw_memory(&mut self, i: u32) -> Result<u32>;
    fn write_shared_rw_memory(&mut self, i: u32, v: u32) -> Result<()>;
    fn set_input_signal(&mut self, hmsb: u32, hlsb: u32, pos: u32) -> Result<()>;
    fn get_witness(&mut self, i: u32) -> Result<()>;
    fn get_witness_size(&self) -> Result<u32>;
}

impl Circom1 for Wasm {
    fn get_fr_len(&self) -> Result<u32> {
        self.get_u32("getFrLen")
    }

    fn get_ptr_raw_prime(&self) -> Result<u32> {
        self.get_u32("getPRawPrime")
    }

    fn get_ptr_witness(&mut self, w: u32) -> Result<u32> {
        let func = self.func("getPWitness");
        let res = func.call(&mut self.store, &[w.into()])?;

        Ok(res[0].unwrap_i32() as u32)
    }

    fn get_signal_offset32(
        &mut self,
        p_sig_offset: u32,
        component: u32,
        hash_msb: u32,
        hash_lsb: u32,
    ) -> Result<()> {
        let func = self.func("getSignalOffset32");
        func.call(
            &mut self.store,
            &[
                p_sig_offset.into(),
                component.into(),
                hash_msb.into(),
                hash_lsb.into(),
            ],
        )?;

        Ok(())
    }

    fn set_signal(&mut self, c_idx: u32, component: u32, signal: u32, p_val: u32) -> Result<()> {
        let func = self.func("setSignal");
        func.call(
            &mut self.store,
            &[c_idx.into(), component.into(), signal.into(), p_val.into()],
        )?;

        Ok(())
    }
}

#[cfg(feature = "circom-2")]
impl Circom2 for Wasm {
    fn get_field_num_len32(&self) -> Result<u32> {
        self.get_u32("getFieldNumLen32")
    }

    fn get_raw_prime(&mut self) -> Result<()> {
        let func = self.func("getRawPrime");
        func.call(&mut self.store, &[])?;
        Ok(())
    }

    fn read_shared_rw_memory(&mut self, i: u32) -> Result<u32> {
        let func = self.func("readSharedRWMemory");
        let result = func.call(&mut self.store, &[i.into()])?;
        Ok(result[0].unwrap_i32() as u32)
    }

    fn write_shared_rw_memory(&mut self, i: u32, v: u32) -> Result<()> {
        let func = self.func("writeSharedRWMemory");
        func.call(&mut self.store, &[i.into(), v.into()])?;
        Ok(())
    }

    fn set_input_signal(&mut self, hmsb: u32, hlsb: u32, pos: u32) -> Result<()> {
        let func = self.func("setInputSignal");
        func.call(&mut self.store, &[hmsb.into(), hlsb.into(), pos.into()])?;
        Ok(())
    }

    fn get_witness(&mut self, i: u32) -> Result<()> {
        let func = self.func("getWitness");
        func.call(&mut self.store, &[i.into()])?;
        Ok(())
    }

    fn get_witness_size(&self) -> Result<u32> {
        self.get_u32("getWitnessSize")
    }
}

impl CircomBase for Wasm {
    fn init(&mut self, sanity_check: bool) -> Result<()> {
        let func = self.func("init");
        func.call(&mut self.store, &[Value::I32(sanity_check as i32)])?;
        Ok(())
    }

    fn get_n_vars(&self) -> Result<u32> {
        self.get_u32("getNVars")
    }

    // Default to version 1 if it isn't explicitly defined
    fn get_version(&mut self) -> Result<u32> {
        match self.instance.exports.get_function("getVersion") {
            Ok(func) => Ok(func.call(&mut self.store, &[])?[0].unwrap_i32() as u32),
            Err(_) => Ok(1),
        }
    }

    fn get_u32(&mut self, name: &str) -> Result<u32> {
        let func = self.func(name);
        let result = func.call(&mut self.store, &[])?;
        Ok(result[0].unwrap_i32() as u32)
    }

    fn func(&self, name: &str) -> &Function {
        self.instance
            .exports
            .get_function(name)
            .unwrap_or_else(|_| panic!("function {} not found", name))
    }
}

impl Wasm {
    pub fn new(instance: Instance, store: Store) -> Self {
        Self { instance, store }
    }
}
