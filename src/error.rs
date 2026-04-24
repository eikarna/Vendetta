use std::io;

use thiserror::Error;

pub type Result<T> = std::result::Result<T, VendettaError>;

#[derive(Debug, Error)]
pub enum VendettaError {
    #[error("configuration error: {0}")]
    Config(String),
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("JSON config error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("TLS error: {0}")]
    Tls(String),
    #[error("SOCKS5 error: {0}")]
    Socks(#[from] SocksError),
    #[error("SSH error: {0}")]
    Ssh(#[from] russh::Error),
    #[error("authentication failed")]
    AuthenticationFailed,
    #[error("password hash error: {0}")]
    PasswordHash(String),
    #[error("egress rejected: {0}")]
    Egress(String),
    #[error("timeout while {0}")]
    Timeout(&'static str),
    #[error("task join error: {0}")]
    Join(String),
}

impl From<rustls::Error> for VendettaError {
    fn from(value: rustls::Error) -> Self {
        Self::Tls(value.to_string())
    }
}

impl From<tokio::task::JoinError> for VendettaError {
    fn from(value: tokio::task::JoinError) -> Self {
        Self::Join(value.to_string())
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SocksError {
    #[error("unsupported SOCKS version {0}")]
    UnsupportedVersion(u8),
    #[error("SOCKS client offered no supported authentication method")]
    UnsupportedMethod,
    #[error("unsupported SOCKS command {0}")]
    UnsupportedCommand(u8),
    #[error("invalid reserved byte {0}")]
    InvalidReserved(u8),
    #[error("unsupported address type {0}")]
    UnsupportedAddressType(u8),
    #[error("domain name cannot be empty")]
    EmptyDomain,
    #[error("domain name is not valid UTF-8")]
    InvalidDomain,
    #[error("truncated SOCKS frame while reading {0}")]
    Truncated(&'static str),
}
