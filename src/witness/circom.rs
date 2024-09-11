use color_eyre::Result;
use wasmer::{Exports, Function, Memory, Store, Value};

#[derive(Debug)]
pub struct Wasm {
    pub exports: Exports,
    pub memory: Memory,
}

impl Wasm {
    pub(crate) fn get_field_num_len32(&self, store: &mut Store) -> Result<u32> {
        self.get_u32(store, "getFieldNumLen32")
    }

    pub(crate) fn get_raw_prime(&self, store: &mut Store) -> Result<()> {
        let func = self.func("getRawPrime");
        func.call(store, &[])?;
        Ok(())
    }

    pub(crate) fn read_shared_rw_memory(&self, store: &mut Store, i: u32) -> Result<u32> {
        let func = self.func("readSharedRWMemory");
        let result = func.call(store, &[i.into()])?;
        Ok(result[0].unwrap_i32() as u32)
    }

    pub(crate) fn write_shared_rw_memory(&self, store: &mut Store, i: u32, v: u32) -> Result<()> {
        let func = self.func("writeSharedRWMemory");
        func.call(store, &[i.into(), v.into()])?;
        Ok(())
    }

    pub(crate) fn set_input_signal(
        &self,
        store: &mut Store,
        hmsb: u32,
        hlsb: u32,
        pos: u32,
    ) -> Result<()> {
        let func = self.func("setInputSignal");
        func.call(store, &[hmsb.into(), hlsb.into(), pos.into()])?;
        Ok(())
    }

    pub(crate) fn get_witness(&self, store: &mut Store, i: u32) -> Result<()> {
        let func = self.func("getWitness");
        func.call(store, &[i.into()])?;
        Ok(())
    }

    pub(crate) fn get_witness_size(&self, store: &mut Store) -> Result<u32> {
        self.get_u32(store, "getWitnessSize")
    }

    pub(crate) fn init(&self, store: &mut Store, sanity_check: bool) -> Result<()> {
        let func = self.func("init");
        func.call(store, &[Value::I32(sanity_check as i32)])?;
        Ok(())
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
    pub fn new(exports: Exports, memory: Memory) -> Self {
        Self { exports, memory }
    }
}
