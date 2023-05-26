mod hazmat;
mod interpolate;

mod constants;
pub use constants::{SHAMIR_MIN_SECRET_SIZE, SHAMIR_MAX_SECRET_SIZE, ShamirError};

mod shamir;
pub use shamir::split_secret;
