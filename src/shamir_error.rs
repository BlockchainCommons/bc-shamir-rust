#[derive(Debug, PartialEq)]
pub enum ShamirError {
    SecretTooLong,
    TooManyShares,
    InterpolationFailure,
    ChecksumFailure,
    SecretTooShort,
    SecretNotEvenLen,
    InvalidThreshold,
    SharesUnequalLength,
}

impl std::fmt::Display for ShamirError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            ShamirError::SecretTooLong => write!(f, "Secret is too long"),
            ShamirError::TooManyShares => write!(f, "Too many shares"),
            ShamirError::InterpolationFailure => write!(f, "Interpolation failed"),
            ShamirError::ChecksumFailure => write!(f, "Checksum failure"),
            ShamirError::SecretTooShort => write!(f, "Secret is too short"),
            ShamirError::SecretNotEvenLen => write!(f, "Secret is not of even length"),
            ShamirError::InvalidThreshold => write!(f, "Invalid threshold"),
            ShamirError::SharesUnequalLength => write!(f, "Shares have unequal length"),
        }
    }
}

impl std::error::Error for ShamirError {}
