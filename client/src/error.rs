use crate::process;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    ReqwestError(#[from] reqwest::Error),
    #[error(transparent)]
    WindowsError(#[from] windows::core::Error),
    #[error(transparent)]
    ProcessError(#[from] process::Error),

    #[error("import not found")]
    ImportNotFound,
    #[error("window not found")]
    WindowNotFound,
    #[error("client error")]
    HttpClientError,
    #[error("timeout")]
    Timeout,
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
