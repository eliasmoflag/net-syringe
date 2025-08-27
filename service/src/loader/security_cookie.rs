use pelite::{
    image::{IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, IMAGE_LOAD_CONFIG_DIRECTORY64},
    pe::{Pe, PeFile},
};

pub fn init_security_cookie(pe: &PeFile, mapped_image: &mut [u8]) -> pelite::Result<()> {
    let load_config = match pe.load_config() {
        Err(pelite::Error::Null) => return Ok(()),
        value => value?,
    };

    let mapped_load_config_dir = pe.data_directory()[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
    if mapped_load_config_dir.VirtualAddress == 0 || mapped_load_config_dir.Size == 0 {
        return Ok(());
    }

    let mapped_load_config = mapped_image
        .get_mut(
            mapped_load_config_dir.VirtualAddress as usize
                ..mapped_load_config_dir.VirtualAddress as usize
                    + std::mem::size_of::<IMAGE_LOAD_CONFIG_DIRECTORY64>(),
        )
        .ok_or(pelite::Error::Overflow)? as *mut _
        as *mut IMAGE_LOAD_CONFIG_DIRECTORY64;

    (unsafe { *mapped_load_config }).SecurityCookie = *load_config.security_cookie()? as u64 + 1;

    Ok(())
}
