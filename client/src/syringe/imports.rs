use crate::{
    dto,
    error::{Error, Result},
};
use std::{collections::HashMap, ffi::CString};
use windows::{
    Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA},
    core::PCSTR,
};

pub fn resolve_imports(
    mut imports: HashMap<String, Vec<dto::Import>>,
) -> Result<HashMap<String, Vec<dto::Import>>> {
    for (dll_name, imports) in &mut imports {
        for import in imports {
            let dll_name = CString::new(dll_name.as_bytes()).map_err(|_| Error::ImportNotFound)?;
            let module_handle = unsafe { LoadLibraryA(PCSTR(dll_name.as_ptr() as _)) }?;

            match import {
                dto::Import::ByName { name, address, .. } => {
                    let import_name =
                        CString::new(name.as_bytes()).map_err(|_| Error::ImportNotFound)?;
                    let procedure =
                        unsafe { GetProcAddress(module_handle, PCSTR(import_name.as_ptr() as _)) }
                            .ok_or(Error::ImportNotFound)?;

                    *address = Some(procedure as _);
                }
                dto::Import::ByOrdinal { ordinal, address } => {
                    if *ordinal == 0 {
                        return Err(Error::ImportNotFound);
                    }

                    let procedure = unsafe {
                        GetProcAddress(module_handle, PCSTR(*ordinal as usize as *const u8))
                    }
                    .ok_or(Error::ImportNotFound)?;

                    *address = Some(procedure as _);
                }
            }
        }
    }
    Ok(imports)
}
