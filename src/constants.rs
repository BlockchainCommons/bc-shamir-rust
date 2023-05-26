pub const SHAMIR_MIN_SECRET_SIZE: usize = 16;
pub const SHAMIR_MAX_SECRET_SIZE: usize = 32;
pub const SHAMIR_MAX_SHARE_COUNT: usize = 16;

#[derive(Debug, PartialEq)]
pub enum ShamirError {
    SecretTooLong,
    TooManyShares,
    InterpolationFailure,
    ChecksumFailure,
    SecretTooShort,
    SecretNotEvenLen,
    InvalidThreshold,
}
