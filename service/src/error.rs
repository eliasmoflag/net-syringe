#[derive(thiserror::Error, Debug)]
pub enum MissingImportError {
    #[error("missing import library {0}")]
    Library(String),
    #[error("missing import by name {0}")]
    Name(String),
    #[error("missing import by ordinal {0}")]
    Ordinal(u16),
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    PeError(#[from] pelite::Error),
    #[error(transparent)]
    MissingImport(#[from] MissingImportError),
    #[error("out of range")]
    OutOfRange,
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
