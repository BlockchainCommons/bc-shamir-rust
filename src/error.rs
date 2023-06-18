#[derive(Debug)]
pub enum Error {
    SecretTooLong,
    TooManyShares,
    InterpolationFailure,
    ChecksumFailure,
    SecretTooShort,
    SecretNotEvenLen,
    InvalidThreshold,
    SharesUnequalLength,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match *self {
            Error::SecretTooLong => "Secret is too long".to_string(),
            Error::TooManyShares => "Too many shares".to_string(),
            Error::InterpolationFailure => "Interpolation failed".to_string(),
            Error::ChecksumFailure => "Checksum failure".to_string(),
            Error::SecretTooShort => "Secret is too short".to_string(),
            Error::SecretNotEvenLen => "Secret is not of even length".to_string(),
            Error::InvalidThreshold => "Invalid threshold".to_string(),
            Error::SharesUnequalLength => "Shares have unequal length".to_string(),
        };
        f.write_str(&s)
    }
}

impl std::error::Error for Error {}
