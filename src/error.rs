use aes_gcm::aes::cipher::InvalidLength;
use hex::FromHexError;
use std::path::StripPrefixError;
use std::str::Utf8Error;
use thiserror::Error;
use walkdir::Error as WalkdirError;
use zip::result::ZipError;

#[derive(Error, Debug)]
pub enum LedgerError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Argon2 error: {0}")]
    Argon2(argon2::password_hash::Error),
    #[error("AesGcm error: {0}")]
    AesGcm(aes_gcm::Error),
    #[error("Invalid encrypted data format")]
    InvalidFormat,
    #[error("Invalid password: {0}")]
    InvalidPassword(String),
    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("Hex decoding error: {0}")]
    Hex(#[from] FromHexError),
    #[error("Invalid AES-GCM length: {0}")]
    InvalidLength(InvalidLength),
    #[error("UTF-8 conversion error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
    #[error("Path prefix stripping error: {0}")]
    PathPrefix(#[from] StripPrefixError),
    #[error("ZIP archive error: {0}")]
    Zip(#[from] ZipError),
    #[error("Directory traversal error: {0}")]
    Walkdir(#[from] WalkdirError),
    #[error("Enrty not Found: {0}")]
    EntryNotFound(String),
}

impl From<argon2::password_hash::Error> for LedgerError {
    fn from(err: argon2::password_hash::Error) -> Self {
        LedgerError::Argon2(err)
    }
}

impl From<aes_gcm::Error> for LedgerError {
    fn from(err: aes_gcm::Error) -> Self {
        LedgerError::AesGcm(err)
    }
}

impl From<InvalidLength> for LedgerError {
    fn from(err: InvalidLength) -> Self {
        LedgerError::InvalidLength(err)
    }
}

impl From<&str> for LedgerError {
    fn from(s: &str) -> Self {
        LedgerError::InvalidPassword(s.to_string())
    }
}
impl From<Utf8Error> for LedgerError {
    fn from(err: Utf8Error) -> Self {
        LedgerError::InvalidPassword(err.to_string())
    }
}
