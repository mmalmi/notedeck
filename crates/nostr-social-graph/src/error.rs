use thiserror::Error;

#[derive(Debug, Error)]
pub enum SocialGraphError {
    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Parse error: {0}")]
    ParseInt(#[from] std::num::ParseIntError),
}
