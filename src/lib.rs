pub const MIN_SECRET_LEN: usize = 16;
pub const MAX_SECRET_LEN: usize = 32;
pub const MAX_SHARE_COUNT: usize = 16;

mod hazmat;
mod interpolate;

mod shamir_error;
pub use shamir_error::ShamirError;

mod shamir;
pub use shamir::{split_secret, recover_secret};
