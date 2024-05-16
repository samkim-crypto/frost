use thiserror::Error;

pub mod client;
pub mod server;

#[derive(Error, Clone, Debug, Eq, PartialEq)]
pub enum DkgError {
    #[error("compressed curve point failed to decompress")]
    Decompression,
    #[error("proof of knowledge failed to verify")]
    ProofOfKnowledge,
    #[error("the share verification failed")]
    ShareVerification,
}
