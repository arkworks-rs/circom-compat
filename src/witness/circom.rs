use color_eyre::Result;
use wasmer::{Function, Instance, Value};

pub enum CircomVersion {
    V1,
    V2
}

// TODO Back to way it was
#[derive(Clone, Debug)]
pub struct Wasm {
    instance: Instance
}

pub trait CircomBase {
    fn init(&self, sanity_check: bool) -> Result<()>;
    fn func(&self, name: &str) -> &Function;
    fn get_ptr_witness_buffer(&self) -> Result<i32>;
    fn get_ptr_witness(&self, w: i32) -> Result<i32>;
    fn get_signal_offset32(
        &self,
        p_sig_offset: u32,
        component: u32,
        hash_msb: u32,
        hash_lsb: u32,
    ) -> Result<()>;
    fn set_signal(&self,
                  c_idx: i32,
                  component: i32,
                  signal: i32,
                  p_val: i32
    ) -> Result<()>;
    fn get_i32(&self, name: &str) -> Result<i32>;
}

pub trait Circom {
    fn get_fr_len(&self) -> Result<i32>;
    fn get_ptr_raw_prime(&self) -> Result<i32>;
    fn get_n_vars(&self) -> Result<i32>;
}

pub trait Circom2 {
    fn get_version(&self) -> Result<i32>;
    fn get_field_num_len32(&self) -> Result<i32>;
    fn get_raw_prime(&self) -> Result<()>;
    fn read_shared_rw_memory(&self, i: i32) -> Result<i32>;
}

impl Circom for Wasm {
    fn get_fr_len(&self) -> Result<i32> {
        self.get_i32("getFrLen")
    }

    fn get_ptr_raw_prime(&self) -> Result<i32> {
        self.get_i32("getPRawPrime")
    }
    fn get_n_vars(&self) -> Result<i32> {
        self.get_i32("getNVars")
    }
}

impl Circom2 for Wasm {
    fn get_version(&self) -> Result<i32> {
        self.get_i32("getVersion")
    }

    fn get_field_num_len32(&self) -> Result<i32> {
        self.get_i32("getFieldNumLen32")
    }

    fn get_raw_prime(&self) -> Result<()> {
        let func = self.func("getRawPrime");
        let _result = func.call(&[])?;
        Ok(())
    }

    fn read_shared_rw_memory(&self, i: i32) -> Result<i32> {
        let func = self.func("readSharedRWMemory");
        let result = func.call(&[i.into()])?;
        Ok(result[0].unwrap_i32())
    }
}

impl CircomBase for Wasm {
    fn init(&self, sanity_check: bool) -> Result<()> {
        let func = self.func("init");
        func.call(&[Value::I32(sanity_check as i32)])?;
        Ok(())
    }

    fn get_ptr_witness_buffer(&self) -> Result<i32> {
        self.get_i32("getWitnessBuffer")
    }

    fn get_ptr_witness(&self, w: i32) -> Result<i32> {
        let func = self.func("getPWitness");
        let res = func.call(&[w.into()])?;

        Ok(res[0].unwrap_i32())
    }

    fn get_signal_offset32(
        &self,
        p_sig_offset: u32,
        component: u32,
        hash_msb: u32,
        hash_lsb: u32,
    ) -> Result<()> {
        let func = self.func("getSignalOffset32");
        func.call(&[
            p_sig_offset.into(),
            component.into(),
            hash_msb.into(),
            hash_lsb.into(),
        ])?;

        Ok(())
    }

    fn set_signal(&self, c_idx: i32, component: i32, signal: i32, p_val: i32) -> Result<()> {
        let func = self.func("setSignal");
        func.call(&[c_idx.into(), component.into(), signal.into(), p_val.into()])?;

        Ok(())
    }

    fn get_i32(&self, name: &str) -> Result<i32> {
        let func = self.func(name);
        let result = func.call(&[])?;
        Ok(result[0].unwrap_i32())
    }

    fn func(&self, name: &str) -> &Function {
        self.instance
            .exports
            .get_function(name)
            .unwrap_or_else(|_| panic!("function {} not found", name))
    }
}

impl Wasm {
    // XXX Do we need version?
    pub fn new(instance: Instance, version: CircomVersion) -> Self {
        Self { instance }
    }
}
