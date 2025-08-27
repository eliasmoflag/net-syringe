#![allow(dead_code)]

pub use error::*;
pub use win32::Win32Process;

pub mod error;
pub mod win32;

pub trait ProcessTrait {
    fn attach(&mut self) -> Result<()>;
    fn detach(&mut self) -> Result<()>;
    fn is_attached(&self) -> bool;
    fn process_id(&self) -> u32;

    fn mem_read(&self, address: u64, buffer: &mut [u8]) -> Result<()>;
    fn mem_write(&self, address: u64, buffer: &[u8]) -> Result<()>;
    fn mem_alloc(
        &self,
        address: Option<u64>,
        size: usize,
        allocation_type: u32,
        protection: u32,
    ) -> Result<u64>;
    fn mem_free(&self, address: u64, size: Option<usize>, allocation_type: u32) -> Result<()>;
    fn mem_protect(&self, address: u64, size: usize, protect: u32) -> Result<u32>;
}
