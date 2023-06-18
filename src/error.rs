#[derive(Debug, PartialEq, Eq, Clone)]
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
        match *self {
            Error::SecretTooLong => write!(f, "Secret is too long"),
            Error::TooManyShares => write!(f, "Too many shares"),
            Error::InterpolationFailure => write!(f, "Interpolation failed"),
            Error::ChecksumFailure => write!(f, "Checksum failure"),
            Error::SecretTooShort => write!(f, "Secret is too short"),
            Error::SecretNotEvenLen => write!(f, "Secret is not of even length"),
            Error::InvalidThreshold => write!(f, "Invalid threshold"),
            Error::SharesUnequalLength => write!(f, "Shares have unequal length"),
        }
    }
}

impl std::error::Error for Error {}
