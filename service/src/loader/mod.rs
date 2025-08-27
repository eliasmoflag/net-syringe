use crate::{
    error::{Error, Result},
    library::Library,
};
pub use imports::*;
use pelite::pe::{Pe, PeFile};
pub use relocations::*;
pub use security_cookie::*;

mod imports;
mod relocations;
mod security_cookie;

pub fn map_image(pe: &PeFile, library: &Library) -> Result<Vec<u8>> {
    let mut mapped_data = Vec::new();
    mapped_data.resize(pe.optional_header().SizeOfImage as usize, 0);

    if library.map_pe_headers {
        let size_of_headers = pe.optional_header().SizeOfHeaders as usize;

        mapped_data
            .get_mut(0..size_of_headers)
            .ok_or(Error::OutOfRange)?
            .copy_from_slice(
                &library
                    .file_data
                    .get(0..size_of_headers)
                    .ok_or(Error::OutOfRange)?,
            );
    }

    for section in pe.section_headers() {
        let raw_data_offset = section.PointerToRawData as usize;
        let virtual_data_offset = section.VirtualAddress as usize;
        let raw_data_size = section.SizeOfRawData as usize;

        let src = library
            .file_data
            .get(raw_data_offset..raw_data_offset + raw_data_size)
            .ok_or(Error::OutOfRange)?;

        let dst = mapped_data
            .get_mut(virtual_data_offset..virtual_data_offset + raw_data_size)
            .ok_or(Error::OutOfRange)?;

        dst.copy_from_slice(src);
    }

    Ok(mapped_data)
}
