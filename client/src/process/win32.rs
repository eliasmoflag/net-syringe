use crate::process::{
    ProcessTrait,
    error::{Error, Result},
};
use std::ffi::c_void;
use windows::Win32::{
    Foundation::{CloseHandle, ERROR_NO_MORE_FILES, HANDLE, INVALID_HANDLE_VALUE},
    System::{
        Diagnostics::{
            Debug::{ReadProcessMemory, WriteProcessMemory},
            ToolHelp::{
                CreateToolhelp32Snapshot, PROCESSENTRY32, Process32First, Process32Next,
                TH32CS_SNAPPROCESS,
            },
        },
        Memory::{
            PAGE_PROTECTION_FLAGS, VIRTUAL_ALLOCATION_TYPE, VIRTUAL_FREE_TYPE, VirtualAllocEx,
            VirtualFreeEx, VirtualProtectEx,
        },
        Threading::{OpenProcess, PROCESS_ALL_ACCESS},
    },
};

pub struct Win32Process {
    process_id: u32,
    process_handle: HANDLE,
}

impl Win32Process {
    pub fn new(process_id: u32) -> Self {
        Self {
            process_id,
            process_handle: INVALID_HANDLE_VALUE,
        }
    }

    pub fn find_process_by_name(process_name: &str) -> Result<Self, Error> {
        let snapshot = match unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) } {
            Ok(handle) => handle,
            Err(error) => return Err(Error::WindowsError(error)),
        };

        let mut entry = PROCESSENTRY32::default();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

        if let Err(error) = unsafe { Process32First(snapshot, &mut entry) } {
            return Err(Error::WindowsError(error));
        }

        let mut process: Option<Self> = None;
        loop {
            let filepath = &entry.szExeFile[0..entry
                .szExeFile
                .iter()
                .position(|c| *c == 0)
                .unwrap_or(entry.szExeFile.len())];

            let filepath = match std::str::from_utf8(unsafe {
                std::slice::from_raw_parts::<u8>(filepath.as_ptr() as *const u8, filepath.len())
            }) {
                Ok(path) => path,
                Err(error) => return Err(Error::Utf8Error(error)),
            };

            if filepath == process_name {
                process = Some(Self::new(entry.th32ProcessID));
                break;
            }

            match unsafe { Process32Next(snapshot, &mut entry) } {
                Ok(_) => (),
                Err(error) => {
                    if error == ERROR_NO_MORE_FILES.into() {
                        break;
                    }
                    return Err(Error::WindowsError(error));
                }
            }
        }

        unsafe { CloseHandle(snapshot).ok() };

        match process {
            Some(process) => Ok(process),
            None => Err(Error::ProcessNotFound),
        }
    }
}

impl ProcessTrait for Win32Process {
    fn attach(&mut self) -> Result<()> {
        if !self.process_handle.is_invalid() {
            return Err(Error::AlreadyAttached);
        }

        self.process_handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, false, self.process_id) }?;

        Ok(())
    }

    fn detach(&mut self) -> Result<()> {
        if self.process_handle.is_invalid() {
            return Err(Error::NotAttached);
        }

        unsafe { CloseHandle(self.process_handle) }?;
        Ok(())
    }

    fn is_attached(&self) -> bool {
        !self.process_handle.is_invalid()
    }

    fn process_id(&self) -> u32 {
        self.process_id
    }

    fn mem_read(&self, address: u64, buffer: &mut [u8]) -> Result<()> {
        if self.process_handle.is_invalid() {
            return Err(Error::NotAttached);
        }

        unsafe {
            ReadProcessMemory(
                self.process_handle,
                address as _,
                buffer.as_mut_ptr() as _,
                buffer.len(),
                None,
            )
        }?;

        Ok(())
    }

    fn mem_write(&self, address: u64, buffer: &[u8]) -> Result<()> {
        if self.process_handle.is_invalid() {
            return Err(Error::NotAttached);
        }

        unsafe {
            WriteProcessMemory(
                self.process_handle,
                address as _,
                buffer.as_ptr() as _,
                buffer.len(),
                None,
            )
        }?;

        Ok(())
    }

    fn mem_alloc(
        &self,
        address: Option<u64>,
        size: usize,
        allocation_type: u32,
        protection: u32,
    ) -> Result<u64> {
        if self.process_handle.is_invalid() {
            return Err(Error::NotAttached);
        }

        let address = address.map(|address| address as *const c_void);

        let allocation = unsafe {
            VirtualAllocEx(
                self.process_handle,
                address,
                size,
                VIRTUAL_ALLOCATION_TYPE(allocation_type),
                PAGE_PROTECTION_FLAGS(protection),
            )
        } as u64;

        if allocation == 0 {
            return Err(Error::FailedAllocation);
        }

        Ok(allocation)
    }

    fn mem_free(&self, address: u64, size: Option<usize>, free_type: u32) -> Result<()> {
        if self.process_handle.is_invalid() {
            return Err(Error::NotAttached);
        }

        unsafe {
            VirtualFreeEx(
                self.process_handle,
                address as _,
                size.unwrap_or(0),
                VIRTUAL_FREE_TYPE(free_type),
            )
        }?;

        Ok(())
    }

    fn mem_protect(&self, address: u64, size: usize, protect: u32) -> Result<u32> {
        if self.process_handle.is_invalid() {
            return Err(Error::NotAttached);
        }

        let mut old_protect = PAGE_PROTECTION_FLAGS::default();
        if let Err(err) = unsafe {
            VirtualProtectEx(
                self.process_handle,
                address as _,
                size,
                PAGE_PROTECTION_FLAGS(protect),
                &mut old_protect,
            )
        } {
            return Err(Error::WindowsError(err));
        }

        Ok(old_protect.0)
    }
}
