use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Import {
    #[serde(rename = "name")]
    ByName {
        hint: usize,
        name: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        address: Option<u64>,
    },
    #[serde(rename = "ordinal")]
    ByOrdinal {
        ordinal: u16,
        #[serde(skip_serializing_if = "Option::is_none")]
        address: Option<u64>,
    },
}

#[derive(Debug, Serialize)]
pub struct Region {
    pub rva: u32,
    pub size: u32,
    pub characteristics: u32,
}

#[derive(Debug, Serialize)]
pub struct GetLibraryResponse {
    pub size_of_image: u32,
    pub entry_point: u32,
    pub imports: HashMap<String, Vec<Import>>,
    pub regions: Vec<Region>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetLibraryMapping {
    pub allocation_base: u64,
    pub imports: HashMap<String, Vec<Import>>,
}
