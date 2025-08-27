#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    WindowsError(#[from] windows::core::Error),
    #[error(transparent)]
    Utf8Error(std::str::Utf8Error),
    #[error("already attached")]
    AlreadyAttached,
    #[error("not attached")]
    NotAttached,
    #[error("process not found")]
    ProcessNotFound,
    #[error("failed allocation")]
    FailedAllocation,
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
