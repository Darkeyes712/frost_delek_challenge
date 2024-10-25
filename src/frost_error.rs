use smol_str::SmolStr;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FrostError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Failed to decompress the public key")]
    DecompressionFailed,

    #[error("Error in Distributed Key Generation: {0}")]
    DkgError(SmolStr),

    #[error("Error transitioning to Round Two")]
    RoundTwoError,

    #[error("Error during signing: {0}")]
    SigningError(SmolStr),

    #[error("An unexpected error occurred: {0}")]
    AnyhowError(#[from] anyhow::Error), // Capture any other errors from anyhow
}
