use thiserror::Error;

pub mod client;
pub mod server;

#[derive(Error, Clone, Debug, Eq, PartialEq)]
pub enum SignError {
    #[error("compressed curve point failed to decompress")]
    Decompression,
    #[error("partial signature failed to verify")]
    PartialSignatureVerification,
}
