use tokio::{fs, io};

pub struct Library {
    pub file_data: Vec<u8>,
    pub map_pe_headers: bool,
    pub init_security_cookie: bool,
}

impl Library {
    pub async fn get(library_id: &str) -> io::Result<Self> {
        if !is_valid_library_id(library_id) {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }

        let file_data = fs::read(format!("assets/libraries/{}", library_id)).await?;

        Ok(Self {
            file_data,
            ..Default::default()
        })
    }
}

impl Default for Library {
    fn default() -> Self {
        Self {
            file_data: Vec::default(),
            map_pe_headers: false,
            init_security_cookie: true,
        }
    }
}

pub fn is_valid_library_id(id: &str) -> bool {
    !id.is_empty()
        && !id.starts_with('.')
        && !id.contains("..")
        && !id.contains("/")
        && !id.contains("\\")
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c.is_numeric() || c == '.' || c == '-')
}
