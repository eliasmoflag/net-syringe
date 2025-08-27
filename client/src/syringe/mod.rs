use crate::{
    dto::{self, GetLibraryMapping},
    error::{Error, Result},
    process::ProcessTrait,
    syringe::{execution::execute_with_windows_hook, imports::resolve_imports},
};
use log::info;
use reqwest::blocking::Client as HttpClient;
use windows::Win32::System::{
    Diagnostics::Debug::{IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_WRITE},
    Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_READWRITE},
};

mod execution;
mod imports;

pub use execution::{ExecutionByWindowsHook, ExecutionMethod};

pub struct Syringe<'p> {
    process: &'p dyn ProcessTrait,
    http_client: HttpClient,
    api_url: String,
}

impl<'p> Syringe<'p> {
    pub fn new<S: Into<String>>(process: &'p dyn ProcessTrait, api_url: S) -> Self {
        let http_client = HttpClient::new();

        Self {
            process,
            http_client,
            api_url: api_url.into(),
        }
    }

    pub fn inject(&self, library_id: &str, execution_method: &ExecutionMethod) -> Result<()> {
        let response = self
            .http_client
            .get(format!("{}/libraries/{}", self.api_url, library_id))
            .send()?;

        if !response.status().is_success() {
            return Err(Error::HttpClientError);
        }

        let library: dto::GetLibraryResponse = response.json()?;

        info!("resolving imports");

        let imports = resolve_imports(library.imports)?;

        info!("allocating space for image");

        let allocation = self.process.mem_alloc(
            None,
            library.size_of_image as usize,
            (MEM_RESERVE | MEM_COMMIT).0,
            PAGE_READWRITE.0,
        )?;
        
        info!("allocated space for image at 0x{:X} (size: 0x{:X})", allocation, library.size_of_image);

        let response = self
            .http_client
            .get(format!("{}/libraries/{}/mapping", self.api_url, library_id))
            .json(&GetLibraryMapping {
                allocation_base: allocation,
                imports,
            })
            .send()?;

        if !response.status().is_success() {
            return Err(Error::HttpClientError);
        }

        let mapping = response.bytes()?;

        info!("writing image to process");

        self.process.mem_write(allocation, &mapping)?;

        info!("applying protections");

        for region in &library.regions {
            let mut protect = PAGE_READWRITE;
            if (region.characteristics & IMAGE_SCN_MEM_EXECUTE.0) != 0 {
                if (region.characteristics & IMAGE_SCN_MEM_WRITE.0) != 0 {
                    protect = PAGE_EXECUTE_READWRITE;
                } else {
                    protect = PAGE_EXECUTE_READ;
                }
            }

            self.process.mem_protect(
                allocation + region.rva as u64,
                region.size as usize,
                protect.0,
            )?;
        }

        match execution_method {
            ExecutionMethod::ByWindowsHook(method) => execute_with_windows_hook(
                self.process,
                allocation,
                allocation + library.entry_point as u64,
                method,
            )?,
        }

        Ok(())
    }
}
