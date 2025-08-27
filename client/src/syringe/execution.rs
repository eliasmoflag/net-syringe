use crate::{
    error::{Error, Result},
    process::ProcessTrait,
};
use log::{error, info};
use std::{
    ffi::CString,
    thread::sleep,
    time::{Duration, Instant},
};
use windows::{
    Win32::{
        Foundation::{HINSTANCE, LPARAM, WPARAM},
        System::{
            LibraryLoader::{GetProcAddress, LoadLibraryA},
            Memory::{MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE},
            SystemServices::DLL_PROCESS_ATTACH,
        },
        UI::WindowsAndMessaging::{
            FindWindowA, GetWindowThreadProcessId, HHOOK, PostThreadMessageA, SetWindowsHookExA,
            UnhookWindowsHookEx, WH_GETMESSAGE, WM_NULL,
        },
    },
    core::PCSTR,
};

#[derive(Debug)]
pub struct ExecutionByWindowsHook {
    pub window_name: Option<String>,
    pub window_class: Option<String>,
    pub timeout: Duration,
}

impl Default for ExecutionByWindowsHook {
    fn default() -> Self {
        Self {
            window_name: None,
            window_class: None,
            timeout: Duration::from_secs(5),
        }
    }
}

#[derive(Debug)]
pub enum ExecutionMethod {
    ByWindowsHook(ExecutionByWindowsHook),
}

impl Into<ExecutionMethod> for ExecutionByWindowsHook {
    fn into(self) -> ExecutionMethod {
        ExecutionMethod::ByWindowsHook(self)
    }
}

#[repr(C)]
struct ShellCodeData {
    status: i32,
    result: i32,

    module_base: u64,
    reason_for_call: u32,
    reserved: u64,

    dllmain: u64,
    callnexthookex: u64,
}

struct ScopedWindowsHookHandle(pub HHOOK);

impl Drop for ScopedWindowsHookHandle {
    fn drop(&mut self) {
        unsafe { UnhookWindowsHookEx(self.0) }.ok();
    }
}

struct ScopedRemoteAllocation<'a>(pub u64, &'a dyn ProcessTrait);

impl Drop for ScopedRemoteAllocation<'_> {
    fn drop(&mut self) {
        self.1.mem_free(self.0, None, MEM_RELEASE.0).ok();
    }
}

pub fn execute_with_windows_hook(
    process: &dyn ProcessTrait,
    module_base: u64,
    entry_point: u64,
    method: &ExecutionByWindowsHook,
) -> Result<()> {
    let user32_dll = unsafe {
        LoadLibraryA(PCSTR(
            CString::new("user32.dll").unwrap().as_ptr() as *const _
        ))
    }?;

    let callnexthookex = unsafe {
        GetProcAddress(
            user32_dll,
            PCSTR(CString::new("CallNextHookEx").unwrap().as_ptr() as *const _),
        )
    }
    .ok_or(Error::ImportNotFound)? as u64;

    let mut shellcode_data = ShellCodeData {
        status: 0,
        result: 0,
        module_base,
        reason_for_call: DLL_PROCESS_ATTACH,
        reserved: 0,
        dllmain: entry_point,
        callnexthookex,
    };

    let mut shellcode: [u8; 143] = [
        0x4c, 0x89, 0x44, 0x24, 0x18, 0x48, 0x89, 0x54, 0x24, 0x10, 0x89, 0x4c, 0x24, 0x08, 0x48,
        0x83, 0xec, 0x38, 0x48, 0xb8, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0x48, 0x89,
        0x44, 0x24, 0x20, 0x48, 0x8b, 0x44, 0x24, 0x20, 0xb9, 0x01, 0x00, 0x00, 0x00, 0x48, 0x89,
        0x44, 0x24, 0x28, 0x33, 0xc0, 0x48, 0x8b, 0x54, 0x24, 0x28, 0x48, 0x8b, 0x54, 0x24, 0x28,
        0xf0, 0x0f, 0xb1, 0x0a, 0x85, 0xc0, 0x74, 0x04, 0x33, 0xc0, 0xeb, 0x42, 0x48, 0x8b, 0x44,
        0x24, 0x20, 0xc7, 0x00, 0x01, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x44, 0x24, 0x20, 0x4c, 0x8b,
        0x40, 0x18, 0x48, 0x8b, 0x44, 0x24, 0x20, 0x8b, 0x50, 0x10, 0x48, 0x8b, 0x44, 0x24, 0x20,
        0x48, 0x8b, 0x48, 0x08, 0x48, 0x8b, 0x44, 0x24, 0x20, 0xff, 0x50, 0x20, 0x48, 0x8b, 0x4c,
        0x24, 0x20, 0x89, 0x41, 0x04, 0x48, 0x8b, 0x44, 0x24, 0x20, 0xc7, 0x00, 0x02, 0x00, 0x00,
        0x00, 0x33, 0xc0, 0x48, 0x83, 0xc4, 0x38, 0xc3,
    ];

    let shellcode_data_alloc = ScopedRemoteAllocation(
        process.mem_alloc(
            None,
            std::mem::size_of_val(&shellcode_data),
            (MEM_RESERVE | MEM_COMMIT).0,
            PAGE_READWRITE.0,
        )?,
        process,
    );

    let shellcode_alloc = ScopedRemoteAllocation(
        process.mem_alloc(
            None,
            std::mem::size_of_val(&shellcode),
            (MEM_RESERVE | MEM_COMMIT).0,
            PAGE_READWRITE.0,
        )?,
        process,
    );

    shellcode[20..28].copy_from_slice(&shellcode_data_alloc.0.to_ne_bytes());

    process.mem_write(shellcode_alloc.0, &shellcode)?;

    process.mem_write(shellcode_data_alloc.0, unsafe {
        std::slice::from_raw_parts(
            &shellcode_data as *const _ as *const u8,
            std::mem::size_of_val(&shellcode_data),
        )
    })?;

    process.mem_protect(
        shellcode_alloc.0,
        std::mem::size_of_val(&shellcode),
        PAGE_EXECUTE_READ.0,
    )?;

    let window_handle = unsafe {
        let window_class = method
            .window_class
            .as_ref()
            .map(|value| CString::new(value.as_bytes()).unwrap());

        let window_name = method
            .window_name
            .as_ref()
            .map(|value| CString::new(value.as_bytes()).unwrap());

        FindWindowA(
            window_class
                .as_ref()
                .map(|value| PCSTR(value.as_ptr() as *const _))
                .unwrap_or(PCSTR(std::ptr::null())),
            window_name
                .as_ref()
                .map(|value| PCSTR(value.as_ptr() as *const _))
                .unwrap_or(PCSTR(std::ptr::null())),
        )
    }
    .map_err(|err| {
        error!("failed to find window: {}", err);
        Error::WindowNotFound
    })?;

    let thread_id = unsafe { GetWindowThreadProcessId(window_handle, None) };
    if thread_id == 0 {
        error!("failed to get window thread process id");
        return Err(Error::WindowNotFound);
    }

    let start_time = Instant::now();

    let _hook_handle = ScopedWindowsHookHandle(unsafe {
        SetWindowsHookExA(
            WH_GETMESSAGE,
            Some(std::mem::transmute(shellcode_alloc.0)),
            Some(HINSTANCE(user32_dll.0)),
            thread_id,
        )
    }?);

    info!("executing shellcode");

    loop {
        unsafe { PostThreadMessageA(thread_id, WM_NULL, WPARAM(0), LPARAM(0)) }?;

        process.mem_read(shellcode_data_alloc.0, unsafe {
            std::slice::from_raw_parts_mut(
                &mut shellcode_data as *mut ShellCodeData as *mut _,
                std::mem::size_of_val(&shellcode_data),
            )
        })?;

        if shellcode_data.status != 0 {
            break;
        }

        if Instant::now() >= start_time + method.timeout {
            return Err(Error::Timeout);
        }

        sleep(Duration::from_millis(10));
    }

    info!("executing main");

    loop {
        unsafe { PostThreadMessageA(thread_id, WM_NULL, WPARAM(0), LPARAM(0)) }?;

        process.mem_read(shellcode_data_alloc.0, unsafe {
            std::slice::from_raw_parts_mut(
                &mut shellcode_data as *mut ShellCodeData as *mut _,
                std::mem::size_of_val(&shellcode_data),
            )
        })?;

        if shellcode_data.status == 2 {
            break;
        }

        if Instant::now() >= start_time + method.timeout {
            return Err(Error::Timeout);
        }

        sleep(Duration::from_millis(10));
    }

    Ok(())
}
