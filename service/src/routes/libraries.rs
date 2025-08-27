use crate::{
    dto::{self, GetLibraryMapping},
    error::Result,
    library::Library,
    loader::{
        apply_relocations, get_library_imports, init_security_cookie, map_image, resolve_imports,
    },
};
use axum::{Json, extract::Path, http::StatusCode};
use pelite::{
    image::{IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE},
    pe::{Pe, PeFile},
};
use tokio::io;
use tracing::{debug, warn};

pub async fn get_library(
    library_id: Path<String>,
) -> Result<Json<dto::GetLibraryResponse>, StatusCode> {
    let library = Library::get(&library_id)
        .await
        .map_err(|err| match err.kind() {
            io::ErrorKind::InvalidInput => StatusCode::BAD_REQUEST,
            io::ErrorKind::NotFound => StatusCode::NOT_FOUND,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        })?;

    let pe =
        PeFile::from_bytes(&library.file_data).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let imports = get_library_imports(&pe).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let regions = pe
        .section_headers()
        .iter()
        .map(|sect| dto::Region {
            rva: sect.VirtualAddress,
            size: sect.VirtualSize,
            characteristics: sect.Characteristics
                & (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE),
        })
        .collect();

    Ok(Json(dto::GetLibraryResponse {
        size_of_image: pe.optional_header().SizeOfImage,
        entry_point: pe.optional_header().AddressOfEntryPoint,
        imports,
        regions,
    }))
}

pub async fn get_library_mapping(
    library_id: Path<String>,
    body: Json<GetLibraryMapping>,
) -> Result<Vec<u8>, StatusCode> {
    debug!(library = library_id.0, "starting mapping");

    if !body.imports.iter().all(|(_, imports)| {
        imports.iter().all(|import| match import {
            dto::Import::ByName { address, .. } => address.is_some(),
            dto::Import::ByOrdinal { address, .. } => address.is_some(),
        })
    }) {
        warn!(
            library = library_id.0,
            "not all import addresses were provided"
        );
        return Err(StatusCode::BAD_REQUEST);
    }

    let library = Library::get(&library_id)
        .await
        .map_err(|err| match err.kind() {
            io::ErrorKind::InvalidInput => StatusCode::BAD_REQUEST,
            io::ErrorKind::NotFound => StatusCode::NOT_FOUND,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        })?;

    let pe =
        PeFile::from_bytes(&library.file_data).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        
    debug!(library = library_id.0, "mapping image");

    let mut mapped_image =
        map_image(&pe, &library).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if library.init_security_cookie {
        debug!(library = library_id.0, "initializing security cookie");

        init_security_cookie(&pe, &mut mapped_image)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }

    debug!(library = library_id.0, "resolving imports");

    resolve_imports(&pe, &mut mapped_image, &body.imports)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    debug!(library = library_id.0, "relocating image");

    apply_relocations(&pe, &mut mapped_image, body.allocation_base)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    debug!(library = library_id.0, "finished mapping");

    Ok(mapped_image)
}
