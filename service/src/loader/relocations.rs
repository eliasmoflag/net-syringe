use crate::error::Result;
use pelite::{
    image::IMAGE_REL_BASED_DIR64,
    pe::{Pe, PeFile},
};

pub fn apply_relocations(
    pe: &PeFile,
    mapped_image: &mut [u8],
    allocation_base: u64,
) -> Result<(), ()> {
    let delta_base = allocation_base.wrapping_sub(pe.optional_header().ImageBase);

    let relocs = match pe.base_relocs() {
        Ok(relocs) => relocs,
        Err(_) => return Ok(()),
    };

    for block in relocs.iter_blocks() {
        for word in block.words() {
            let ty = block.type_of(word);
            if ty == IMAGE_REL_BASED_DIR64 {
                let rva = block.rva_of(word) as usize;

                let slot: &mut [u8; 8] = mapped_image
                    .get_mut(rva..rva + 8)
                    .ok_or(())?
                    .try_into()
                    .map_err(|_| ())?;

                *slot = u64::from_ne_bytes(*slot)
                    .wrapping_add(delta_base)
                    .to_ne_bytes();
            }
        }
    }

    Ok(())
}
