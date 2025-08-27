use crate::{
    dto,
    error::{Error, MissingImportError, Result},
};
use pelite::pe::{Pe, PeFile, imports::Import};
use std::collections::HashMap;

pub fn get_library_imports(pe: &PeFile) -> pelite::Result<HashMap<String, Vec<dto::Import>>> {
    let mut imports: HashMap<String, Vec<dto::Import>> = HashMap::new();

    for desc in pe.imports()? {
        let dll_name = desc.dll_name()?;

        let mut dll_imports: Vec<dto::Import> = Vec::new();

        for imp in desc.int()? {
            match imp? {
                Import::ByName { hint, name } => dll_imports.push(dto::Import::ByName {
                    hint: hint,
                    name: name.to_string(),
                    address: None,
                }),
                Import::ByOrdinal { ord } => dll_imports.push(dto::Import::ByOrdinal {
                    ordinal: ord,
                    address: None,
                }),
            }
        }

        imports.insert(dll_name.to_string(), dll_imports);
    }

    Ok(imports)
}

fn as_u64_mut(slice: &mut [u8]) -> Option<&mut u64> {
    if slice.len() >= 8 && slice.as_ptr().align_offset(std::mem::align_of::<u64>()) == 0 {
        Some(unsafe { &mut *(slice.as_mut_ptr() as *mut u64) })
    } else {
        None
    }
}

pub fn resolve_imports(
    pe: &PeFile,
    mapped_image: &mut [u8],
    exports: &HashMap<String, Vec<dto::Import>>,
) -> Result<()> {
    let imports = match pe.imports() {
        Ok(imports) => imports,
        Err(pelite::Error::Null) => return Ok(()),
        Err(err) => return Err(err.into()),
    };

    for desc in imports {
        let dll_name = desc.dll_name()?.to_string();

        let exports = exports
            .get(&dll_name)
            .ok_or(Error::MissingImport(MissingImportError::Library(dll_name)))?;

        for (idx, imp) in desc.int()?.enumerate() {
            let first_thunk_rva = desc.image().FirstThunk as usize + idx * 8;
            let address = as_u64_mut(
                mapped_image
                    .get_mut(first_thunk_rva..first_thunk_rva + 8)
                    .ok_or(Error::PeError(pelite::Error::Overflow))?,
            )
            .ok_or(pelite::Error::Misaligned)?;

            match imp? {
                Import::ByName { name, .. } => {
                    *address = exports
                        .iter()
                        .find_map(|imp| match imp {
                            dto::Import::ByName {
                                name: imp_name,
                                address,
                                ..
                            } => {
                                if name == imp_name {
                                    return *address;
                                }
                                None
                            }
                            _ => None,
                        })
                        .ok_or(Error::MissingImport(MissingImportError::Name(
                            name.to_string(),
                        )))?;
                }
                Import::ByOrdinal { ord } => {
                    *address = exports
                        .iter()
                        .find_map(|imp| match imp {
                            dto::Import::ByOrdinal { ordinal, address } => {
                                if ord == *ordinal {
                                    return *address;
                                }
                                None
                            }
                            _ => None,
                        })
                        .ok_or(Error::MissingImport(MissingImportError::Ordinal(ord)))?;
                }
            }
        }
    }

    Ok(())
}
