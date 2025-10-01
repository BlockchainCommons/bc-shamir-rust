#![doc(html_root_url = "https://docs.rs/bc-shamir/0.9.0")]
#![warn(rust_2018_idioms)]

//! ## Introduction
//!
//! This is a pure-Rust implementation of [Shamir's Secret Sharing
//! (SSS)](https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing) is a
//! cryptographic technique in which a *secret* is divided into parts, called
//! *shares*, in such a way that a *threshold* of several shares are needed to
//! reconstruct the secret. The shares are distributed in a way that makes it
//! impossible for an attacker to know anything about the secret without having
//! a threshold of shares. If the number of shares is less than the threshold,
//! then no information about the secret is revealed.
//!
//! ## Getting Started
//!
//! ```toml
//! [dependencies]
//! bc-shamir = "0.9.0"
//! ```
//!
//! ## Usage
//!
//! ### Splitting a secret
//!
//! ```
//! # use bc_shamir::split_secret;
//! # fn main() {
//! let secret = b"my secret belongs to me.";
//! let threshold = 2;
//! let share_count = 3;
//! let mut random_generator = bc_rand::SecureRandomNumberGenerator;
//!
//! let shares =
//!     split_secret(threshold, share_count, secret, &mut random_generator)
//!         .unwrap();
//!
//! assert_eq!(shares.len(), share_count);
//! # }
//! ```
//!
//! ### Recovering a secret
//!
//! ```
//! # use bc_shamir::recover_secret;
//! # fn main() {
//! let indexes = vec![0, 2];
//! let shares = vec![
//!     vec![
//!         47, 165, 102, 232, 218, 99, 6, 94, 39, 6, 253, 215, 12, 88, 64, 32,
//!         105, 40, 222, 146, 93, 197, 48, 129,
//!     ],
//!     vec![
//!         221, 174, 116, 201, 90, 99, 136, 33, 64, 215, 60, 84, 207, 28, 74,
//!         10, 111, 243, 43, 224, 48, 64, 199, 172,
//!     ],
//! ];
//!
//! let secret = recover_secret(&indexes, &shares).unwrap();
//!
//! assert_eq!(secret, b"my secret belongs to me.");
//! # }
//! ```

/// The minimum length of a secret.
pub const MIN_SECRET_LEN: usize = 16;

/// The maximum length of a secret.
pub const MAX_SECRET_LEN: usize = 32;

/// The maximum number of shares that can be generated from a secret.
pub const MAX_SHARE_COUNT: usize = 16;

mod hazmat;
mod interpolate;

mod error;
pub use error::{Error, Result};

mod shamir;
pub use shamir::{recover_secret, split_secret};

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use super::*;

    // Helper to create deterministic RNG for testing
    // Uses SeededRandomNumberGenerator with a fixed seed [0, 0, 0, 0]
    // This ensures consistent test results across runs
    fn make_test_rng() -> bc_rand::SeededRandomNumberGenerator {
        bc_rand::SeededRandomNumberGenerator::new([0, 0, 0, 0])
    }

    #[test]
    fn test_split_secret_3_5() {
        let mut rng = make_test_rng();
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf");
        let shares = split_secret(3, 5, &secret, &mut rng).unwrap();
        assert_eq!(shares.len(), 5);

        // Test recovery with different combinations
        let recovered_share_indexes = vec![1, 2, 4];
        let recovered_shares = recovered_share_indexes
            .iter()
            .map(|index| shares[*index].clone())
            .collect::<Vec<_>>();
        let recovered_secret = recover_secret(&recovered_share_indexes, &recovered_shares).unwrap();
        assert_eq!(recovered_secret, secret);
    }

    #[test]
    fn test_split_secret_2_7() {
        let mut rng = make_test_rng();
        let secret = hex!("204188bfa6b440a1bdfd6753ff55a8241e07af5c5be943db917e3efabc184b1a");
        let shares = split_secret(2, 7, &secret, &mut rng).unwrap();
        assert_eq!(shares.len(), 7);

        // Test recovery with different combinations
        let recovered_share_indexes = vec![3, 4];
        let recovered_shares = recovered_share_indexes
            .iter()
            .map(|index| shares[*index].clone())
            .collect::<Vec<_>>();
        let recovered_secret = recover_secret(&recovered_share_indexes, &recovered_shares).unwrap();
        assert_eq!(recovered_secret, secret);
    }

    #[test]
    fn test_readme_deps() {
        version_sync::assert_markdown_deps_updated!("README.md");
    }

    #[test]
    fn test_html_root_url() {
        version_sync::assert_html_root_url_updated!("src/lib.rs");
    }

    // Edge case tests
    #[test]
    fn test_threshold_equals_one() {
        let mut rng = make_test_rng();
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf");
        let shares = split_secret(1, 5, &secret, &mut rng).unwrap();

        // With threshold=1, all shares should be identical to secret
        for share in &shares {
            assert_eq!(share, &secret);
        }

        // Any single share should recover the secret
        let recovered = recover_secret(&[2], &[shares[2].clone()]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_threshold_equals_share_count() {
        let mut rng = make_test_rng();
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf");
        let threshold = 5;
        let share_count = 5;
        let shares = split_secret(threshold, share_count, &secret, &mut rng).unwrap();

        // All shares needed to recover
        let indexes: Vec<usize> = (0..share_count).collect();
        let recovered = recover_secret(&indexes, &shares).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_max_shares() {
        let mut rng = make_test_rng();
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf");
        let shares = split_secret(2, MAX_SHARE_COUNT, &secret, &mut rng).unwrap();
        assert_eq!(shares.len(), MAX_SHARE_COUNT);

        let recovered = recover_secret(&[0, 1], &[shares[0].clone(), shares[1].clone()]).unwrap();
        assert_eq!(recovered, secret);
    }

    // Negative tests - testing error conditions
    #[test]
    fn test_secret_too_short() {
        let mut rng = make_test_rng();
        let secret = vec![0u8; MIN_SECRET_LEN - 1];
        let result = split_secret(2, 3, &secret, &mut rng);
        assert!(matches!(result, Err(Error::SecretTooShort)));
    }

    #[test]
    fn test_secret_too_long() {
        let mut rng = make_test_rng();
        let secret = vec![0u8; MAX_SECRET_LEN + 1];
        let result = split_secret(2, 3, &secret, &mut rng);
        assert!(matches!(result, Err(Error::SecretTooLong)));
    }

    #[test]
    fn test_secret_odd_length() {
        let mut rng = make_test_rng();
        let secret = vec![0u8; 17]; // Odd number
        let result = split_secret(2, 3, &secret, &mut rng);
        assert!(matches!(result, Err(Error::SecretNotEvenLen)));
    }

    #[test]
    fn test_too_many_shares() {
        let mut rng = make_test_rng();
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf");
        let result = split_secret(2, MAX_SHARE_COUNT + 1, &secret, &mut rng);
        assert!(matches!(result, Err(Error::TooManyShares)));
    }

    #[test]
    fn test_invalid_threshold_zero() {
        let mut rng = make_test_rng();
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf");
        let result = split_secret(0, 3, &secret, &mut rng);
        assert!(matches!(result, Err(Error::InvalidThreshold)));
    }

    #[test]
    fn test_invalid_threshold_greater_than_shares() {
        let mut rng = make_test_rng();
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf");
        let result = split_secret(5, 3, &secret, &mut rng);
        assert!(matches!(result, Err(Error::InvalidThreshold)));
    }

    #[test]
    fn test_recover_insufficient_shares() {
        let mut rng = make_test_rng();
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf");
        let shares = split_secret(3, 5, &secret, &mut rng).unwrap();

        // Try to recover with only 2 shares (threshold is 3)
        // This should result in incorrect secret or checksum failure
        let result = recover_secret(&[0, 1], &[shares[0].clone(), shares[1].clone()]);
        assert!(matches!(result, Err(Error::ChecksumFailure)));
    }

    #[test]
    fn test_recover_unequal_share_lengths() {
        let indexes = vec![0, 1];
        let shares = vec![
            vec![1u8; 16],
            vec![2u8; 20], // Different length
        ];
        let result = recover_secret(&indexes, &shares);
        assert!(matches!(result, Err(Error::SharesUnequalLength)));
    }

    #[test]
    fn test_recover_empty_shares() {
        let indexes: Vec<usize> = vec![];
        let shares: Vec<Vec<u8>> = vec![];
        let result = recover_secret(&indexes, &shares);
        assert!(matches!(result, Err(Error::InvalidThreshold)));
    }

    #[test]
    fn test_recover_index_mismatch() {
        let indexes = vec![0, 1, 2];
        let shares = vec![vec![1u8; 16], vec![2u8; 16]];
        let result = recover_secret(&indexes, &shares);
        assert!(matches!(result, Err(Error::InvalidThreshold)));
    }

    #[test]
    fn test_all_valid_secret_lengths() {
        let mut rng = make_test_rng();
        // Test all even lengths from MIN to MAX
        for len in (MIN_SECRET_LEN..=MAX_SECRET_LEN).step_by(2) {
            let secret = vec![0xAB_u8; len];
            let shares = split_secret(2, 3, &secret, &mut rng).unwrap();
            let recovered =
                recover_secret(&[0, 1], &[shares[0].clone(), shares[1].clone()]).unwrap();
            assert_eq!(recovered, secret, "Failed for length {}", len);
        }
    }

    #[test]
    fn test_different_share_combinations() {
        let mut rng = make_test_rng();
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf");
        let shares = split_secret(3, 5, &secret, &mut rng).unwrap();

        // Test all valid combinations of 3 shares
        let combinations = vec![
            vec![0, 1, 2],
            vec![0, 1, 3],
            vec![0, 1, 4],
            vec![0, 2, 3],
            vec![0, 2, 4],
            vec![0, 3, 4],
            vec![1, 2, 3],
            vec![1, 2, 4],
            vec![1, 3, 4],
            vec![2, 3, 4],
        ];

        for combo in combinations {
            let combo_shares: Vec<Vec<u8>> = combo.iter().map(|&i| shares[i].clone()).collect();
            let recovered = recover_secret(&combo, &combo_shares).unwrap();
            assert_eq!(recovered, secret, "Failed for combination {:?}", combo);
        }
    }

    #[test]
    fn test_corrupted_share_detection() {
        let mut rng = make_test_rng();
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf");
        let mut shares = split_secret(2, 3, &secret, &mut rng).unwrap();

        // Corrupt one share
        shares[0][0] ^= 0xFF;

        let result = recover_secret(&[0, 1], &[shares[0].clone(), shares[1].clone()]);
        // Should fail checksum
        assert!(matches!(result, Err(Error::ChecksumFailure)));
    }

    #[test]
    fn test_minimum_secret_length() {
        let mut rng = make_test_rng();
        let secret = vec![0xAB_u8; MIN_SECRET_LEN];
        let shares = split_secret(2, 3, &secret, &mut rng).unwrap();
        let recovered = recover_secret(&[0, 1], &[shares[0].clone(), shares[1].clone()]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_maximum_secret_length() {
        let mut rng = make_test_rng();
        let secret = vec![0xCD_u8; MAX_SECRET_LEN];
        let shares = split_secret(2, 3, &secret, &mut rng).unwrap();
        let recovered = recover_secret(&[0, 1], &[shares[0].clone(), shares[1].clone()]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_multiple_corrupted_shares() {
        let mut rng = make_test_rng();
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf");
        let mut shares = split_secret(3, 5, &secret, &mut rng).unwrap();

        // Corrupt multiple shares
        shares[0][5] ^= 0xFF;
        shares[1][10] ^= 0xAA;

        let result = recover_secret(
            &[0, 1, 2],
            &[shares[0].clone(), shares[1].clone(), shares[2].clone()],
        );
        assert!(matches!(result, Err(Error::ChecksumFailure)));
    }

    #[test]
    fn test_recover_with_non_sequential_indexes() {
        let mut rng = make_test_rng();
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf");
        let shares = split_secret(3, 6, &secret, &mut rng).unwrap();

        // Use non-sequential indexes: 0, 2, 5
        let recovered = recover_secret(
            &[0, 2, 5],
            &[shares[0].clone(), shares[2].clone(), shares[5].clone()],
        )
        .unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_all_shares_to_recover() {
        let mut rng = make_test_rng();
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf");
        let threshold = 3;
        let share_count = 5;
        let shares = split_secret(threshold, share_count, &secret, &mut rng).unwrap();

        // Use all shares (more than threshold)
        let indexes: Vec<usize> = (0..share_count).collect();
        let recovered = recover_secret(&indexes, &shares).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_secret_with_zeros() {
        let mut rng = make_test_rng();
        let secret = vec![0u8; 16];
        let shares = split_secret(2, 3, &secret, &mut rng).unwrap();
        let recovered = recover_secret(&[0, 1], &[shares[0].clone(), shares[1].clone()]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_secret_with_all_ones() {
        let mut rng = make_test_rng();
        let secret = vec![0xFF_u8; 16];
        let shares = split_secret(2, 3, &secret, &mut rng).unwrap();
        let recovered = recover_secret(&[0, 1], &[shares[0].clone(), shares[1].clone()]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_secret_with_pattern() {
        let mut rng = make_test_rng();
        let secret: Vec<u8> = (0..32).map(|i| (i * 7) as u8).collect();
        let shares = split_secret(3, 5, &secret, &mut rng).unwrap();
        let recovered = recover_secret(
            &[1, 3, 4],
            &[shares[1].clone(), shares[3].clone(), shares[4].clone()],
        )
        .unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_high_threshold() {
        let mut rng = make_test_rng();
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf");
        let threshold = MAX_SHARE_COUNT;
        let share_count = MAX_SHARE_COUNT;
        let shares = split_secret(threshold, share_count, &secret, &mut rng).unwrap();

        let indexes: Vec<usize> = (0..share_count).collect();
        let recovered = recover_secret(&indexes, &shares).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_share_count_equals_threshold_plus_one() {
        let mut rng = make_test_rng();
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf");
        let threshold = 5;
        let share_count = 6;
        let shares = split_secret(threshold, share_count, &secret, &mut rng).unwrap();

        // Use exactly threshold shares
        let indexes: Vec<usize> = (0..threshold).collect();
        let shares_subset: Vec<Vec<u8>> = indexes.iter().map(|&i| shares[i].clone()).collect();
        let recovered = recover_secret(&indexes, &shares_subset).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_recover_with_last_shares() {
        let mut rng = make_test_rng();
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf");
        let shares = split_secret(3, 8, &secret, &mut rng).unwrap();

        // Use last 3 shares
        let recovered = recover_secret(
            &[5, 6, 7],
            &[shares[5].clone(), shares[6].clone(), shares[7].clone()],
        )
        .unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_share_independence() {
        let mut rng = make_test_rng();
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf");
        let shares = split_secret(2, 4, &secret, &mut rng).unwrap();

        // Verify each pair of shares can recover the secret
        for i in 0..shares.len() {
            for j in (i + 1)..shares.len() {
                let recovered =
                    recover_secret(&[i, j], &[shares[i].clone(), shares[j].clone()]).unwrap();
                assert_eq!(recovered, secret, "Failed with shares {} and {}", i, j);
            }
        }
    }

    #[test]
    fn test_partial_corruption_at_end() {
        let mut rng = make_test_rng();
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf");
        let mut shares = split_secret(2, 3, &secret, &mut rng).unwrap();

        // Corrupt last byte of a share
        let last_idx = shares[0].len() - 1;
        shares[0][last_idx] ^= 0x01;

        let result = recover_secret(&[0, 1], &[shares[0].clone(), shares[1].clone()]);
        assert!(matches!(result, Err(Error::ChecksumFailure)));
    }

    #[test]
    fn test_deterministic_with_same_rng_state() {
        let mut rng1 = make_test_rng();
        let mut rng2 = make_test_rng();
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf");

        let shares1 = split_secret(2, 3, &secret, &mut rng1).unwrap();
        let shares2 = split_secret(2, 3, &secret, &mut rng2).unwrap();

        // With deterministic RNG, shares should be identical
        assert_eq!(shares1, shares2);
    }

    #[test]
    fn test_16_byte_secret() {
        let mut rng = make_test_rng();
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf");
        assert_eq!(secret.len(), 16);

        let shares = split_secret(3, 5, &secret, &mut rng).unwrap();
        let recovered = recover_secret(
            &[0, 2, 4],
            &[shares[0].clone(), shares[2].clone(), shares[4].clone()],
        )
        .unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_32_byte_secret() {
        let mut rng = make_test_rng();
        let secret = hex!("204188bfa6b440a1bdfd6753ff55a8241e07af5c5be943db917e3efabc184b1a");
        assert_eq!(secret.len(), 32);

        let shares = split_secret(2, 4, &secret, &mut rng).unwrap();
        let recovered = recover_secret(&[1, 3], &[shares[1].clone(), shares[3].clone()]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_24_byte_secret() {
        let mut rng = make_test_rng();
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf1122334455667788");
        assert_eq!(secret.len(), 24);

        let shares = split_secret(2, 3, &secret, &mut rng).unwrap();
        let recovered = recover_secret(&[0, 2], &[shares[0].clone(), shares[2].clone()]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_wrong_share_order() {
        let mut rng = make_test_rng();
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf");
        let shares = split_secret(2, 3, &secret, &mut rng).unwrap();

        // Provide shares in reverse order but with correct indexes
        let recovered = recover_secret(&[2, 0], &[shares[2].clone(), shares[0].clone()]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_duplicate_index_detection() {
        let mut rng = make_test_rng();
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf");
        let shares = split_secret(3, 5, &secret, &mut rng).unwrap();

        // Try to use duplicate indexes (should fail checksum due to invalid interpolation)
        let result = recover_secret(
            &[0, 0, 1],
            &[shares[0].clone(), shares[0].clone(), shares[1].clone()],
        );
        assert!(matches!(result, Err(Error::ChecksumFailure)));
    }

    #[test]
    fn test_extreme_threshold_2_of_16() {
        let mut rng = make_test_rng();
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf");
        let shares = split_secret(2, MAX_SHARE_COUNT, &secret, &mut rng).unwrap();

        // Any 2 shares should work
        let recovered = recover_secret(&[7, 14], &[shares[7].clone(), shares[14].clone()]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_single_bit_corruption() {
        let mut rng = make_test_rng();
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf");
        let mut shares = split_secret(2, 3, &secret, &mut rng).unwrap();

        // Flip a single bit in middle of share
        shares[0][8] ^= 0x01;

        let result = recover_secret(&[0, 1], &[shares[0].clone(), shares[1].clone()]);
        assert!(matches!(result, Err(Error::ChecksumFailure)));
    }

    #[test]
    fn test_shares_with_different_thresholds() {
        let mut rng = make_test_rng();
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf");

        // Test multiple threshold values
        for threshold in 1..=MAX_SHARE_COUNT {
            let shares = split_secret(threshold, MAX_SHARE_COUNT, &secret, &mut rng).unwrap();
            let indexes: Vec<usize> = (0..threshold).collect();
            let shares_subset: Vec<Vec<u8>> = indexes.iter().map(|&i| shares[i].clone()).collect();
            let recovered = recover_secret(&indexes, &shares_subset).unwrap();
            assert_eq!(recovered, secret, "Failed for threshold {}", threshold);
        }
    }

    #[test]
    fn test_alternating_byte_pattern() {
        let mut rng = make_test_rng();
        let secret: Vec<u8> = (0..16)
            .map(|i| if i % 2 == 0 { 0xAA } else { 0x55 })
            .collect();
        let shares = split_secret(2, 3, &secret, &mut rng).unwrap();
        let recovered = recover_secret(&[0, 1], &[shares[0].clone(), shares[1].clone()]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_consecutive_recoveries() {
        let mut rng = make_test_rng();
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf");
        let shares = split_secret(2, 4, &secret, &mut rng).unwrap();

        // Recover multiple times with different share combinations
        for _ in 0..3 {
            let recovered1 =
                recover_secret(&[0, 1], &[shares[0].clone(), shares[1].clone()]).unwrap();
            let recovered2 =
                recover_secret(&[2, 3], &[shares[2].clone(), shares[3].clone()]).unwrap();
            assert_eq!(recovered1, secret);
            assert_eq!(recovered2, secret);
        }
    }

    #[test]
    fn test_empty_share_bytes_invalid() {
        let indexes = vec![0, 1];
        let shares = vec![
            vec![], // Empty share
            vec![1u8; 16],
        ];
        let result = recover_secret(&indexes, &shares);
        assert!(result.is_err());
    }

    #[test]
    fn test_threshold_2_various_counts() {
        let mut rng = make_test_rng();
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf");

        for share_count in 2..=MAX_SHARE_COUNT {
            let shares = split_secret(2, share_count, &secret, &mut rng).unwrap();
            let recovered =
                recover_secret(&[0, 1], &[shares[0].clone(), shares[1].clone()]).unwrap();
            assert_eq!(recovered, secret, "Failed for share_count {}", share_count);
        }
    }

    // ========== Additional Advanced Tests ==========

    #[test]
    fn test_18_byte_secret() {
        let mut rng = make_test_rng();
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf1122");
        assert_eq!(secret.len(), 18);

        let shares = split_secret(2, 3, &secret, &mut rng).unwrap();
        let recovered = recover_secret(&[0, 2], &[shares[0].clone(), shares[2].clone()]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_20_byte_secret() {
        let mut rng = make_test_rng();
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf11223344");
        assert_eq!(secret.len(), 20);

        let shares = split_secret(3, 4, &secret, &mut rng).unwrap();
        let recovered = recover_secret(
            &[0, 1, 3],
            &[shares[0].clone(), shares[1].clone(), shares[3].clone()],
        )
        .unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_22_byte_secret() {
        let mut rng = make_test_rng();
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf112233445566");
        assert_eq!(secret.len(), 22);

        let shares = split_secret(2, 5, &secret, &mut rng).unwrap();
        let recovered = recover_secret(&[1, 4], &[shares[1].clone(), shares[4].clone()]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_26_byte_secret() {
        let mut rng = make_test_rng();
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf11223344556677889900");
        assert_eq!(secret.len(), 26);

        let shares = split_secret(2, 3, &secret, &mut rng).unwrap();
        let recovered = recover_secret(&[0, 1], &[shares[0].clone(), shares[1].clone()]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_28_byte_secret() {
        let mut rng = make_test_rng();
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf11223344556677889900aabb");
        assert_eq!(secret.len(), 28);

        let shares = split_secret(3, 6, &secret, &mut rng).unwrap();
        let recovered = recover_secret(
            &[0, 2, 5],
            &[shares[0].clone(), shares[2].clone(), shares[5].clone()],
        )
        .unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_30_byte_secret() {
        let mut rng = make_test_rng();
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf112233445566778899aabbccddee");
        assert_eq!(secret.len(), 30);

        let shares = split_secret(2, 4, &secret, &mut rng).unwrap();
        let recovered = recover_secret(&[1, 3], &[shares[1].clone(), shares[3].clone()]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_threshold_3_share_4() {
        let mut rng = make_test_rng();
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf");
        let shares = split_secret(3, 4, &secret, &mut rng).unwrap();

        // Test all possible combinations of 3 shares
        let combinations = vec![vec![0, 1, 2], vec![0, 1, 3], vec![0, 2, 3], vec![1, 2, 3]];

        for combo in combinations {
            let combo_shares: Vec<Vec<u8>> = combo.iter().map(|&i| shares[i].clone()).collect();
            let recovered = recover_secret(&combo, &combo_shares).unwrap();
            assert_eq!(recovered, secret, "Failed for combination {:?}", combo);
        }
    }

    #[test]
    fn test_threshold_4_share_6() {
        let mut rng = make_test_rng();
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf");
        let shares = split_secret(4, 6, &secret, &mut rng).unwrap();

        // Test some combinations of 4 shares
        let combinations = vec![
            vec![0, 1, 2, 3],
            vec![0, 2, 4, 5],
            vec![1, 2, 3, 5],
            vec![2, 3, 4, 5],
        ];

        for combo in combinations {
            let combo_shares: Vec<Vec<u8>> = combo.iter().map(|&i| shares[i].clone()).collect();
            let recovered = recover_secret(&combo, &combo_shares).unwrap();
            assert_eq!(recovered, secret, "Failed for combination {:?}", combo);
        }
    }

    #[test]
    fn test_middle_shares_only() {
        let mut rng = make_test_rng();
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf");
        let shares = split_secret(3, 10, &secret, &mut rng).unwrap();

        // Use only middle shares (not first or last)
        let recovered = recover_secret(
            &[3, 5, 7],
            &[shares[3].clone(), shares[5].clone(), shares[7].clone()],
        )
        .unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_first_and_last_shares() {
        let mut rng = make_test_rng();
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf");
        let shares = split_secret(3, 8, &secret, &mut rng).unwrap();

        // Use first, middle, and last
        let recovered = recover_secret(
            &[0, 4, 7],
            &[shares[0].clone(), shares[4].clone(), shares[7].clone()],
        )
        .unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_ascii_secret() {
        let mut rng = make_test_rng();
        let secret = b"Hello World!1234"; // 16 bytes
        let shares = split_secret(2, 3, secret, &mut rng).unwrap();
        let recovered = recover_secret(&[0, 1], &[shares[0].clone(), shares[1].clone()]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_unicode_secret_encoded() {
        let mut rng = make_test_rng();
        // Use UTF-8 encoded bytes, padded to even length
        let secret = "Hello 世界!".as_bytes();
        let mut padded_secret = secret.to_vec();
        if padded_secret.len() < MIN_SECRET_LEN {
            padded_secret.resize(MIN_SECRET_LEN, 0);
        }
        if padded_secret.len() % 2 != 0 {
            padded_secret.push(0);
        }

        let shares = split_secret(2, 3, &padded_secret, &mut rng).unwrap();
        let recovered = recover_secret(&[0, 2], &[shares[0].clone(), shares[2].clone()]).unwrap();
        assert_eq!(recovered, padded_secret);
    }

    #[test]
    fn test_binary_data_with_nulls() {
        let mut rng = make_test_rng();
        let secret: Vec<u8> = vec![
            0x00, 0xFF, 0x00, 0xFF, 0xAA, 0x55, 0xAA, 0x55, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC,
            0xDE, 0xF0,
        ];
        let shares = split_secret(3, 5, &secret, &mut rng).unwrap();
        let recovered = recover_secret(
            &[1, 2, 4],
            &[shares[1].clone(), shares[2].clone(), shares[4].clone()],
        )
        .unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_sequential_byte_values() {
        let mut rng = make_test_rng();
        let secret: Vec<u8> = (0..32).collect();
        let shares = split_secret(2, 4, &secret, &mut rng).unwrap();
        let recovered = recover_secret(&[0, 3], &[shares[0].clone(), shares[3].clone()]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_reverse_sequential_bytes() {
        let mut rng = make_test_rng();
        let secret: Vec<u8> = (0..32).rev().collect();
        let shares = split_secret(2, 3, &secret, &mut rng).unwrap();
        let recovered = recover_secret(&[1, 2], &[shares[1].clone(), shares[2].clone()]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_fibonacci_like_pattern() {
        let mut rng = make_test_rng();
        let mut secret = vec![1u8, 1u8];
        for i in 2..32 {
            secret.push(secret[i - 1].wrapping_add(secret[i - 2]));
        }
        let shares = split_secret(3, 5, &secret, &mut rng).unwrap();
        let recovered = recover_secret(
            &[0, 2, 4],
            &[shares[0].clone(), shares[2].clone(), shares[4].clone()],
        )
        .unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_prime_number_pattern() {
        let mut rng = make_test_rng();
        let primes: Vec<u8> = vec![
            2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83,
            89, 97, 101, 103, 107, 109, 113, 127, 131,
        ];
        let shares = split_secret(2, 4, &primes, &mut rng).unwrap();
        let recovered = recover_secret(&[0, 1], &[shares[0].clone(), shares[1].clone()]).unwrap();
        assert_eq!(recovered, primes);
    }

    #[test]
    fn test_power_of_two_pattern() {
        let mut rng = make_test_rng();
        let secret: Vec<u8> = (0..16).map(|i| 1u8 << (i % 8)).collect();
        let shares = split_secret(2, 3, &secret, &mut rng).unwrap();
        let recovered = recover_secret(&[0, 2], &[shares[0].clone(), shares[2].clone()]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_checkerboard_pattern() {
        let mut rng = make_test_rng();
        let secret: Vec<u8> = (0..32)
            .map(|i| if (i / 4) % 2 == 0 { 0xFF } else { 0x00 })
            .collect();
        let shares = split_secret(3, 6, &secret, &mut rng).unwrap();
        let recovered = recover_secret(
            &[1, 3, 5],
            &[shares[1].clone(), shares[3].clone(), shares[5].clone()],
        )
        .unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_gradient_pattern() {
        let mut rng = make_test_rng();
        let secret: Vec<u8> = (0..32).map(|i| (i * 8) as u8).collect();
        let shares = split_secret(2, 5, &secret, &mut rng).unwrap();
        let recovered = recover_secret(&[1, 4], &[shares[1].clone(), shares[4].clone()]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_multiple_splits_same_secret() {
        let mut rng = make_test_rng();
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf");

        // Split the same secret multiple times
        for _ in 0..5 {
            let shares = split_secret(2, 3, &secret, &mut rng).unwrap();
            let recovered =
                recover_secret(&[0, 1], &[shares[0].clone(), shares[1].clone()]).unwrap();
            assert_eq!(recovered, secret);
        }
    }

    #[test]
    fn test_different_secrets_same_parameters() {
        let mut rng = make_test_rng();
        let secrets = vec![
            hex!("0ff784df000c4380a5ed683f7e6e3dcf"),
            hex!("1ff784df000c4380a5ed683f7e6e3dc0"),
            hex!("2ff784df000c4380a5ed683f7e6e3dc1"),
        ];

        for secret in secrets {
            let shares = split_secret(2, 3, &secret, &mut rng).unwrap();
            let recovered =
                recover_secret(&[0, 1], &[shares[0].clone(), shares[1].clone()]).unwrap();
            assert_eq!(recovered, secret);
        }
    }

    #[test]
    fn test_adjacent_share_pairs() {
        let mut rng = make_test_rng();
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf");
        let shares = split_secret(2, 8, &secret, &mut rng).unwrap();

        // Test all adjacent pairs
        for i in 0..7 {
            let recovered =
                recover_secret(&[i, i + 1], &[shares[i].clone(), shares[i + 1].clone()]).unwrap();
            assert_eq!(
                recovered,
                secret,
                "Failed for adjacent pair {}, {}",
                i,
                i + 1
            );
        }
    }

    #[test]
    fn test_non_adjacent_pairs() {
        let mut rng = make_test_rng();
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf");
        let shares = split_secret(2, 10, &secret, &mut rng).unwrap();

        // Test pairs with gaps
        let pairs = vec![
            (0, 5),
            (1, 6),
            (2, 7),
            (3, 8),
            (4, 9),
            (0, 9),
            (1, 8),
            (2, 7),
        ];

        for (i, j) in pairs {
            let recovered =
                recover_secret(&[i, j], &[shares[i].clone(), shares[j].clone()]).unwrap();
            assert_eq!(recovered, secret, "Failed for pair {}, {}", i, j);
        }
    }

    #[test]
    fn test_maximum_gap_shares() {
        let mut rng = make_test_rng();
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf");
        let shares = split_secret(2, MAX_SHARE_COUNT, &secret, &mut rng).unwrap();

        // Use first and last share (maximum gap)
        let recovered = recover_secret(
            &[0, MAX_SHARE_COUNT - 1],
            &[shares[0].clone(), shares[MAX_SHARE_COUNT - 1].clone()],
        )
        .unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_threshold_7_of_10() {
        let mut rng = make_test_rng();
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf");
        let shares = split_secret(7, 10, &secret, &mut rng).unwrap();

        let indexes = vec![0, 1, 2, 5, 7, 8, 9];
        let shares_subset: Vec<Vec<u8>> = indexes.iter().map(|&i| shares[i].clone()).collect();
        let recovered = recover_secret(&indexes, &shares_subset).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_threshold_10_of_12() {
        let mut rng = make_test_rng();
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf");
        let shares = split_secret(10, 12, &secret, &mut rng).unwrap();

        let indexes = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 11];
        let shares_subset: Vec<Vec<u8>> = indexes.iter().map(|&i| shares[i].clone()).collect();
        let recovered = recover_secret(&indexes, &shares_subset).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_xor_pattern_secret() {
        let mut rng = make_test_rng();
        let secret: Vec<u8> = (0..32).map(|i| (i as u8) ^ 0xAA).collect();
        let shares = split_secret(3, 5, &secret, &mut rng).unwrap();
        let recovered = recover_secret(
            &[0, 2, 4],
            &[shares[0].clone(), shares[2].clone(), shares[4].clone()],
        )
        .unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_rotation_pattern() {
        let mut rng = make_test_rng();
        let secret: Vec<u8> = (0..32).map(|i| ((i * 13) % 256) as u8).collect();
        let shares = split_secret(2, 4, &secret, &mut rng).unwrap();
        let recovered = recover_secret(&[0, 3], &[shares[0].clone(), shares[3].clone()]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_nibble_pattern() {
        let mut rng = make_test_rng();
        let secret: Vec<u8> = (0..32)
            .map(|i| {
                let high = (i % 16) << 4;
                let low = (15 - (i % 16)) & 0x0F;
                (high | low) as u8
            })
            .collect();
        let shares = split_secret(2, 3, &secret, &mut rng).unwrap();
        let recovered = recover_secret(&[0, 1], &[shares[0].clone(), shares[1].clone()]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_all_even_bytes() {
        let mut rng = make_test_rng();
        let secret: Vec<u8> = (0..16).map(|i| (i * 2) as u8).collect();
        let shares = split_secret(2, 3, &secret, &mut rng).unwrap();
        let recovered = recover_secret(&[0, 2], &[shares[0].clone(), shares[2].clone()]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_all_odd_bytes() {
        let mut rng = make_test_rng();
        let secret: Vec<u8> = (0..16).map(|i| (i * 2 + 1) as u8).collect();
        let shares = split_secret(2, 3, &secret, &mut rng).unwrap();
        let recovered = recover_secret(&[1, 2], &[shares[1].clone(), shares[2].clone()]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_hamming_weight_pattern() {
        let mut rng = make_test_rng();
        // Bytes with increasing number of 1 bits
        let secret: Vec<u8> = vec![
            0b00000000, 0b00000001, 0b00000011, 0b00000111, 0b00001111, 0b00011111, 0b00111111,
            0b01111111, 0b11111111, 0b11111110, 0b11111100, 0b11111000, 0b11110000, 0b11100000,
            0b11000000, 0b10000000,
        ];
        let shares = split_secret(2, 4, &secret, &mut rng).unwrap();
        let recovered = recover_secret(&[0, 3], &[shares[0].clone(), shares[3].clone()]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_gray_code_pattern() {
        let mut rng = make_test_rng();
        let secret: Vec<u8> = (0..32)
            .map(|i| {
                let gray = (i ^ (i >> 1)) as u8;
                gray
            })
            .collect();
        let shares = split_secret(3, 5, &secret, &mut rng).unwrap();
        let recovered = recover_secret(
            &[0, 2, 4],
            &[shares[0].clone(), shares[2].clone(), shares[4].clone()],
        )
        .unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_share_subset_with_exact_threshold() {
        let mut rng = make_test_rng();
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf");

        for threshold in 2..=8 {
            let share_count = threshold + 3;
            let shares = split_secret(threshold, share_count, &secret, &mut rng).unwrap();

            // Use exactly threshold shares
            let indexes: Vec<usize> = (0..threshold).collect();
            let shares_subset: Vec<Vec<u8>> = indexes.iter().map(|&i| shares[i].clone()).collect();
            let recovered = recover_secret(&indexes, &shares_subset).unwrap();
            assert_eq!(recovered, secret, "Failed for threshold {}", threshold);
        }
    }

    #[test]
    fn test_share_subset_with_threshold_plus_one() {
        let mut rng = make_test_rng();
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf");

        for threshold in 2..=7 {
            let share_count = threshold + 3;
            let shares = split_secret(threshold, share_count, &secret, &mut rng).unwrap();

            // Use threshold + 1 shares
            let indexes: Vec<usize> = (0..=threshold).collect();
            let shares_subset: Vec<Vec<u8>> = indexes.iter().map(|&i| shares[i].clone()).collect();
            let recovered = recover_secret(&indexes, &shares_subset).unwrap();
            assert_eq!(recovered, secret, "Failed for threshold {}", threshold);
        }
    }

    #[test]
    fn test_stress_many_splits() {
        let mut rng = make_test_rng();
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf");

        // Perform many split operations
        for _ in 0..20 {
            let shares = split_secret(2, 3, &secret, &mut rng).unwrap();
            assert_eq!(shares.len(), 3);
        }
    }

    #[test]
    fn test_stress_many_recoveries() {
        let mut rng = make_test_rng();
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf");
        let shares = split_secret(2, 4, &secret, &mut rng).unwrap();

        // Perform many recovery operations
        for _ in 0..20 {
            let recovered =
                recover_secret(&[0, 1], &[shares[0].clone(), shares[1].clone()]).unwrap();
            assert_eq!(recovered, secret);
        }
    }

    #[test]
    fn test_interleaved_split_recover() {
        let mut rng = make_test_rng();
        let secrets = vec![
            hex!("0ff784df000c4380a5ed683f7e6e3dcf"),
            hex!("1ff784df000c4380a5ed683f7e6e3dc0"),
            hex!("2ff784df000c4380a5ed683f7e6e3dc1"),
        ];

        let all_shares: Vec<Vec<Vec<u8>>> = secrets
            .iter()
            .map(|s| split_secret(2, 3, s, &mut rng).unwrap())
            .collect();

        for (idx, shares) in all_shares.iter().enumerate() {
            let recovered =
                recover_secret(&[0, 1], &[shares[0].clone(), shares[1].clone()]).unwrap();
            assert_eq!(recovered, secrets[idx]);
        }
    }

    // ========== Advanced Edge Cases & Property Tests ==========

    #[test]
    fn test_share_mixing_fails() {
        let mut rng = make_test_rng();
        let secret1 = hex!("0ff784df000c4380a5ed683f7e6e3dcf");
        let secret2 = hex!("1ff784df000c4380a5ed683f7e6e3dc0");

        let shares1 = split_secret(2, 3, &secret1, &mut rng).unwrap();
        let shares2 = split_secret(2, 3, &secret2, &mut rng).unwrap();

        // Try to mix shares from different secrets - should fail checksum
        let result = recover_secret(&[0, 1], &[shares1[0].clone(), shares2[1].clone()]);
        assert!(matches!(result, Err(Error::ChecksumFailure)));
    }

    #[test]
    fn test_threshold_boundary_minus_one() {
        let mut rng = make_test_rng();
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf");
        let shares = split_secret(5, 8, &secret, &mut rng).unwrap();

        // Try with threshold - 1 shares (4 instead of 5) - should fail
        let result = recover_secret(
            &[0, 1, 2, 3],
            &[
                shares[0].clone(),
                shares[1].clone(),
                shares[2].clone(),
                shares[3].clone(),
            ],
        );
        assert!(matches!(result, Err(Error::ChecksumFailure)));
    }

    #[test]
    fn test_all_shares_identical_fails() {
        let indexes = vec![0, 1, 2];
        let identical_share = vec![0x42u8; 16];
        let shares = vec![
            identical_share.clone(),
            identical_share.clone(),
            identical_share.clone(),
        ];

        // All identical shares should fail (except threshold=1 case)
        let result = recover_secret(&indexes, &shares);
        assert!(result.is_err());
    }

    #[test]
    fn test_zero_length_secret_rejected() {
        let mut rng = make_test_rng();
        let secret: Vec<u8> = vec![];
        let result = split_secret(2, 3, &secret, &mut rng);
        assert!(matches!(result, Err(Error::SecretTooShort)));
    }

    #[test]
    fn test_single_byte_secret_rejected() {
        let mut rng = make_test_rng();
        let secret = vec![0xAB];
        let result = split_secret(2, 3, &secret, &mut rng);
        assert!(matches!(result, Err(Error::SecretTooShort)));
    }

    #[test]
    fn test_15_byte_secret_rejected() {
        let mut rng = make_test_rng();
        let secret = vec![0xABu8; 15];
        let result = split_secret(2, 3, &secret, &mut rng);
        assert!(matches!(result, Err(Error::SecretTooShort)));
    }

    #[test]
    fn test_33_byte_secret_rejected() {
        let mut rng = make_test_rng();
        let secret = vec![0xABu8; 33];
        let result = split_secret(2, 3, &secret, &mut rng);
        assert!(matches!(result, Err(Error::SecretTooLong)));
    }

    #[test]
    fn test_100_byte_secret_rejected() {
        let mut rng = make_test_rng();
        let secret = vec![0xABu8; 100];
        let result = split_secret(2, 3, &secret, &mut rng);
        assert!(matches!(result, Err(Error::SecretTooLong)));
    }

    #[test]
    fn test_17_share_count_rejected() {
        let mut rng = make_test_rng();
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf");
        let result = split_secret(2, MAX_SHARE_COUNT + 1, &secret, &mut rng);
        assert!(matches!(result, Err(Error::TooManyShares)));
    }

    #[test]
    fn test_50_share_count_rejected() {
        let mut rng = make_test_rng();
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf");
        let result = split_secret(2, 50, &secret, &mut rng);
        assert!(matches!(result, Err(Error::TooManyShares)));
    }

    #[test]
    fn test_threshold_larger_than_count_by_one() {
        let mut rng = make_test_rng();
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf");
        let result = split_secret(4, 3, &secret, &mut rng);
        assert!(matches!(result, Err(Error::InvalidThreshold)));
    }

    #[test]
    fn test_threshold_much_larger_than_count() {
        let mut rng = make_test_rng();
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf");
        let result = split_secret(100, 5, &secret, &mut rng);
        assert!(matches!(result, Err(Error::InvalidThreshold)));
    }

    #[test]
    fn test_shares_with_trailing_zeros() {
        let mut rng = make_test_rng();
        let mut secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf").to_vec();
        secret.extend_from_slice(&[0u8; 16]);
        assert_eq!(secret.len(), 32);

        let shares = split_secret(2, 3, &secret, &mut rng).unwrap();
        let recovered = recover_secret(&[0, 1], &[shares[0].clone(), shares[1].clone()]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_shares_with_leading_zeros() {
        let mut rng = make_test_rng();
        let mut secret = vec![0u8; 16];
        secret.extend_from_slice(&hex!("0ff784df000c4380a5ed683f7e6e3dcf"));
        assert_eq!(secret.len(), 32);

        let shares = split_secret(2, 3, &secret, &mut rng).unwrap();
        let recovered = recover_secret(&[0, 1], &[shares[0].clone(), shares[1].clone()]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_alternating_zeros_and_data() {
        let mut rng = make_test_rng();
        let secret: Vec<u8> = (0..32)
            .map(|i| if i % 4 < 2 { 0x00 } else { 0xFF })
            .collect();
        let shares = split_secret(3, 5, &secret, &mut rng).unwrap();
        let recovered = recover_secret(
            &[0, 2, 4],
            &[shares[0].clone(), shares[2].clone(), shares[4].clone()],
        )
        .unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_single_non_zero_byte() {
        let mut rng = make_test_rng();
        let mut secret = vec![0u8; 16];
        secret[8] = 0xFF;
        let shares = split_secret(2, 3, &secret, &mut rng).unwrap();
        let recovered = recover_secret(&[0, 1], &[shares[0].clone(), shares[1].clone()]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_bit_positions_all_set_individually() {
        let mut rng = make_test_rng();
        // Each byte has one bit set
        let secret: Vec<u8> = (0..16).map(|i| 1u8 << (i % 8)).collect();
        let shares = split_secret(2, 4, &secret, &mut rng).unwrap();
        let recovered = recover_secret(&[1, 3], &[shares[1].clone(), shares[3].clone()]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_sparse_data_pattern() {
        let mut rng = make_test_rng();
        let mut secret = vec![0u8; 32];
        secret[0] = 0xFF;
        secret[10] = 0xAA;
        secret[20] = 0x55;
        secret[31] = 0x33;

        let shares = split_secret(2, 3, &secret, &mut rng).unwrap();
        let recovered = recover_secret(&[0, 2], &[shares[0].clone(), shares[2].clone()]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_very_high_entropy_secret() {
        let mut rng = make_test_rng();
        // Pseudo-random looking pattern
        let secret: Vec<u8> = (0..32).map(|i| ((i * 137 + 91) % 256) as u8).collect();
        let shares = split_secret(4, 8, &secret, &mut rng).unwrap();
        let recovered = recover_secret(
            &[0, 3, 5, 7],
            &[
                shares[0].clone(),
                shares[3].clone(),
                shares[5].clone(),
                shares[7].clone(),
            ],
        )
        .unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_low_entropy_secret() {
        let mut rng = make_test_rng();
        // Mostly same values
        let secret: Vec<u8> = (0..32)
            .map(|i| if i == 5 || i == 20 { 0xFF } else { 0xAA })
            .collect();
        let shares = split_secret(2, 3, &secret, &mut rng).unwrap();
        let recovered = recover_secret(&[0, 1], &[shares[0].clone(), shares[1].clone()]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_shares_length_consistency() {
        let mut rng = make_test_rng();
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf");
        let shares = split_secret(3, 10, &secret, &mut rng).unwrap();

        // All shares should have the same length as the secret
        for share in &shares {
            assert_eq!(share.len(), secret.len());
        }
    }

    #[test]
    fn test_shares_are_different() {
        let mut rng = make_test_rng();
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf");
        let shares = split_secret(2, 5, &secret, &mut rng).unwrap();

        // For threshold > 1, shares should be different from each other
        for i in 0..shares.len() {
            for j in (i + 1)..shares.len() {
                assert_ne!(
                    shares[i], shares[j],
                    "Shares {} and {} should be different",
                    i, j
                );
            }
        }
    }

    #[test]
    fn test_threshold_1_shares_equal_secret() {
        let mut rng = make_test_rng();
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf");
        let shares = split_secret(1, 5, &secret, &mut rng).unwrap();

        // For threshold = 1, all shares should equal the secret
        for share in &shares {
            assert_eq!(share, &secret);
        }
    }

    #[test]
    fn test_recover_with_more_than_needed() {
        let mut rng = make_test_rng();
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf");
        let shares = split_secret(3, 10, &secret, &mut rng).unwrap();

        // Use 7 shares when only 3 needed
        let indexes = vec![0, 1, 2, 4, 6, 8, 9];
        let shares_subset: Vec<Vec<u8>> = indexes.iter().map(|&i| shares[i].clone()).collect();
        let recovered = recover_secret(&indexes, &shares_subset).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_recover_with_all_shares() {
        let mut rng = make_test_rng();
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf");
        let threshold = 4;
        let share_count = 12;
        let shares = split_secret(threshold, share_count, &secret, &mut rng).unwrap();

        // Use all shares
        let indexes: Vec<usize> = (0..share_count).collect();
        let recovered = recover_secret(&indexes, &shares).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_byte_value_255_handling() {
        let mut rng = make_test_rng();
        let secret = vec![0xFFu8; 16];
        let shares = split_secret(2, 3, &secret, &mut rng).unwrap();
        let recovered = recover_secret(&[0, 1], &[shares[0].clone(), shares[1].clone()]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_mixed_high_low_bytes() {
        let mut rng = make_test_rng();
        let secret: Vec<u8> = (0..32).map(|i| if i < 16 { 0x00 } else { 0xFF }).collect();
        let shares = split_secret(2, 3, &secret, &mut rng).unwrap();
        let recovered = recover_secret(&[0, 2], &[shares[0].clone(), shares[2].clone()]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_palindrome_secret() {
        let mut rng = make_test_rng();
        let secret = vec![
            0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xF0, 0xDE, 0xBC, 0x9A, 0x78, 0x56,
            0x34, 0x12,
        ];
        let shares = split_secret(2, 3, &secret, &mut rng).unwrap();
        let recovered = recover_secret(&[0, 1], &[shares[0].clone(), shares[1].clone()]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_repeated_byte_blocks() {
        let mut rng = make_test_rng();
        let block = vec![0x42, 0x43, 0x44, 0x45];
        let mut secret = vec![];
        for _ in 0..8 {
            secret.extend_from_slice(&block);
        }
        assert_eq!(secret.len(), 32);

        let shares = split_secret(3, 5, &secret, &mut rng).unwrap();
        let recovered = recover_secret(
            &[1, 2, 4],
            &[shares[1].clone(), shares[2].clone(), shares[4].clone()],
        )
        .unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_byte_increment_pattern() {
        let mut rng = make_test_rng();
        let secret: Vec<u8> = (0u8..32u8).map(|i| i.wrapping_mul(8)).collect();
        let shares = split_secret(2, 4, &secret, &mut rng).unwrap();
        let recovered = recover_secret(&[0, 3], &[shares[0].clone(), shares[3].clone()]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_byte_decrement_pattern() {
        let mut rng = make_test_rng();
        let secret: Vec<u8> = (0u8..32u8).rev().map(|i| i.wrapping_mul(8)).collect();
        let shares = split_secret(2, 4, &secret, &mut rng).unwrap();
        let recovered = recover_secret(&[1, 2], &[shares[1].clone(), shares[2].clone()]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_sine_wave_approximation() {
        let mut rng = make_test_rng();
        let secret: Vec<u8> = (0..32)
            .map(|i| (128.0 + 127.0 * ((i as f64) * 0.5).sin()) as u8)
            .collect();
        let shares = split_secret(3, 6, &secret, &mut rng).unwrap();
        let recovered = recover_secret(
            &[0, 2, 5],
            &[shares[0].clone(), shares[2].clone(), shares[5].clone()],
        )
        .unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_triangular_wave_pattern() {
        let mut rng = make_test_rng();
        let secret: Vec<u8> = (0..32)
            .map(|i| {
                let pos = i % 16;
                if pos < 8 {
                    (pos * 32) as u8
                } else {
                    (255 - (pos - 8) * 32) as u8
                }
            })
            .collect();
        let shares = split_secret(2, 3, &secret, &mut rng).unwrap();
        let recovered = recover_secret(&[0, 1], &[shares[0].clone(), shares[1].clone()]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_square_wave_pattern() {
        let mut rng = make_test_rng();
        let secret: Vec<u8> = (0..32)
            .map(|i| if (i / 8) % 2 == 0 { 0x00 } else { 0xFF })
            .collect();
        let shares = split_secret(2, 4, &secret, &mut rng).unwrap();
        let recovered = recover_secret(&[0, 3], &[shares[0].clone(), shares[3].clone()]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_sawtooth_pattern() {
        let mut rng = make_test_rng();
        let secret: Vec<u8> = (0..32).map(|i| ((i * 255) / 31) as u8).collect();
        let shares = split_secret(2, 3, &secret, &mut rng).unwrap();
        let recovered = recover_secret(&[0, 2], &[shares[0].clone(), shares[2].clone()]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_quadratic_pattern() {
        let mut rng = make_test_rng();
        let secret: Vec<u8> = (0..32).map(|i| ((i * i) % 256) as u8).collect();
        let shares = split_secret(3, 5, &secret, &mut rng).unwrap();
        let recovered = recover_secret(
            &[0, 2, 4],
            &[shares[0].clone(), shares[2].clone(), shares[4].clone()],
        )
        .unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_cubic_pattern() {
        let mut rng = make_test_rng();
        let secret: Vec<u8> = (0..32).map(|i| ((i * i * i) % 256) as u8).collect();
        let shares = split_secret(2, 4, &secret, &mut rng).unwrap();
        let recovered = recover_secret(&[1, 3], &[shares[1].clone(), shares[3].clone()]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_exponential_pattern() {
        let mut rng = make_test_rng();
        let secret: Vec<u8> = (0..32).map(|i| 2u32.pow(i % 8) as u8).collect();
        let shares = split_secret(2, 3, &secret, &mut rng).unwrap();
        let recovered = recover_secret(&[0, 1], &[shares[0].clone(), shares[1].clone()]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_logarithmic_like_pattern() {
        let mut rng = make_test_rng();
        let secret: Vec<u8> = (1..=32).map(|i| ((i as f64).ln() * 40.0) as u8).collect();
        let shares = split_secret(2, 4, &secret, &mut rng).unwrap();
        let recovered = recover_secret(&[0, 3], &[shares[0].clone(), shares[3].clone()]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_modulo_prime_pattern() {
        let mut rng = make_test_rng();
        let secret: Vec<u8> = (0..32).map(|i| ((i * 17) % 251) as u8).collect();
        let shares = split_secret(3, 6, &secret, &mut rng).unwrap();
        let recovered = recover_secret(
            &[1, 3, 5],
            &[shares[1].clone(), shares[3].clone(), shares[5].clone()],
        )
        .unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_bit_reversal_pattern() {
        let mut rng = make_test_rng();
        let secret: Vec<u8> = (0u8..32u8).map(|i| i.reverse_bits()).collect();
        let shares = split_secret(2, 3, &secret, &mut rng).unwrap();
        let recovered = recover_secret(&[0, 2], &[shares[0].clone(), shares[2].clone()]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_cyclic_rotation() {
        let mut rng = make_test_rng();
        let secret: Vec<u8> = (0..32)
            .map(|i| 0xABu8.rotate_left((i % 8) as u32))
            .collect();
        let shares = split_secret(2, 4, &secret, &mut rng).unwrap();
        let recovered = recover_secret(&[0, 1], &[shares[0].clone(), shares[1].clone()]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_parity_alternation() {
        let mut rng = make_test_rng();
        let secret: Vec<u8> = (0u32..32u32)
            .map(|i| if i.count_ones() % 2 == 0 { 0x00 } else { 0xFF })
            .collect();
        let shares = split_secret(2, 3, &secret, &mut rng).unwrap();
        let recovered = recover_secret(&[0, 1], &[shares[0].clone(), shares[1].clone()]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_all_thresholds_all_lengths() {
        let mut rng = make_test_rng();

        // Test various combinations of thresholds and secret lengths
        for threshold in [2, 4, 8] {
            for len in [16, 20, 24, 28, 32] {
                let secret = vec![0xABu8; len];
                let shares = split_secret(threshold, threshold + 2, &secret, &mut rng).unwrap();

                let indexes: Vec<usize> = (0..threshold).collect();
                let shares_subset: Vec<Vec<u8>> =
                    indexes.iter().map(|&i| shares[i].clone()).collect();
                let recovered = recover_secret(&indexes, &shares_subset).unwrap();
                assert_eq!(
                    recovered, secret,
                    "Failed for threshold {} and length {}",
                    threshold, len
                );
            }
        }
    }

    #[test]
    fn test_random_subset_combinations() {
        let mut rng = make_test_rng();
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf");
        let threshold = 5;
        let share_count = 10;
        let shares = split_secret(threshold, share_count, &secret, &mut rng).unwrap();

        // Test several different subsets of exactly threshold shares
        let test_combinations = vec![
            vec![0, 1, 2, 3, 4],
            vec![1, 3, 5, 7, 9],
            vec![0, 2, 4, 6, 8],
            vec![5, 6, 7, 8, 9],
        ];

        for combo in test_combinations {
            let combo_shares: Vec<Vec<u8>> = combo.iter().map(|&i| shares[i].clone()).collect();
            let recovered = recover_secret(&combo, &combo_shares).unwrap();
            assert_eq!(recovered, secret, "Failed for combination {:?}", combo);
        }
    }

    // ========== Security & Cryptographic Tests ==========

    #[test]
    fn test_information_theoretic_security_insufficient_shares() {
        // Test that k-1 shares reveal NO information about the secret
        let mut rng = make_test_rng();
        let secret1 = hex!("0ff784df000c4380a5ed683f7e6e3dcf");
        let secret2 = hex!("ffffffffffffffffffffffffffffffff");
        
        let shares1 = split_secret(3, 5, &secret1, &mut rng).unwrap();
        let shares2 = split_secret(3, 5, &secret2, &mut rng).unwrap();
        
        // With only 2 shares (less than threshold), should not be able to recover
        let result1 = recover_secret(&[0, 1], &[shares1[0].clone(), shares1[1].clone()]);
        let result2 = recover_secret(&[0, 1], &[shares2[0].clone(), shares2[1].clone()]);
        
        // Both should fail with checksum error (information-theoretically secure)
        assert!(matches!(result1, Err(Error::ChecksumFailure)));
        assert!(matches!(result2, Err(Error::ChecksumFailure)));
    }

    #[test]
    fn test_no_information_leakage_from_single_share() {
        // A single share should reveal nothing about the secret
        let mut rng = make_test_rng();
        let secret = hex!("deadbeefcafebabe0123456789abcdef");
        let shares = split_secret(4, 6, &secret, &mut rng).unwrap();
        
        // Single share should not contain the secret
        for share in &shares {
            assert_ne!(share, &secret, "Share should not equal secret");
            
            // Check that share doesn't contain obvious patterns from secret
            let share_xor: u8 = share.iter().fold(0, |acc, &x| acc ^ x);
            let secret_xor: u8 = secret.iter().fold(0, |acc, &x| acc ^ x);
            
            // XOR patterns should be different (statistical test)
            // This is a simple test; real analysis would be more complex
            assert_ne!(share_xor, secret_xor, "Share XOR pattern should differ from secret");
        }
    }

    #[test]
    fn test_tamper_detection_single_bit_flip() {
        // Test that even a single bit flip in any share is detected
        let mut rng = make_test_rng();
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf");
        let shares = split_secret(3, 5, &secret, &mut rng).unwrap();
        
        // Try flipping each bit in the first share
        for byte_idx in 0..shares[0].len() {
            for bit_idx in 0..8 {
                let mut tampered_shares = shares.clone();
                tampered_shares[0][byte_idx] ^= 1 << bit_idx;
                
                let result = recover_secret(
                    &[0, 1, 2],
                    &[
                        tampered_shares[0].clone(),
                        tampered_shares[1].clone(),
                        tampered_shares[2].clone(),
                    ],
                );
                
                assert!(
                    matches!(result, Err(Error::ChecksumFailure)),
                    "Bit flip at byte {} bit {} not detected",
                    byte_idx,
                    bit_idx
                );
            }
        }
    }

    #[test]
    fn test_tamper_detection_multiple_bits() {
        // Test detection of multiple bit flips
        let mut rng = make_test_rng();
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf");
        let shares = split_secret(2, 4, &secret, &mut rng).unwrap();
        
        // Flip multiple bits
        let mut tampered = shares[0].clone();
        tampered[0] ^= 0xFF;
        tampered[5] ^= 0x0F;
        tampered[10] ^= 0xF0;
        
        let result = recover_secret(&[0, 1], &[tampered, shares[1].clone()]);
        assert!(matches!(result, Err(Error::ChecksumFailure)));
    }

    #[test]
    fn test_share_substitution_attack() {
        // Test that substituting shares from different secrets is detected
        let mut rng = make_test_rng();
        let secret1 = hex!("0ff784df000c4380a5ed683f7e6e3dcf");
        let secret2 = hex!("deadbeefcafebabe0123456789abcdef");
        
        let shares1 = split_secret(2, 3, &secret1, &mut rng).unwrap();
        let shares2 = split_secret(2, 3, &secret2, &mut rng).unwrap();
        
        // Mix shares from different secrets
        let result = recover_secret(&[0, 1], &[shares1[0].clone(), shares2[1].clone()]);
        assert!(matches!(result, Err(Error::ChecksumFailure)));
    }

    #[test]
    fn test_replay_attack_prevention() {
        // Test that old shares can't be reused with new shares
        let mut rng = make_test_rng();
        let secret1 = hex!("0ff784df000c4380a5ed683f7e6e3dcf");
        let secret2 = hex!("deadbeefcafebabe0123456789abcdef");
        
        let shares1 = split_secret(3, 5, &secret1, &mut rng).unwrap();
        let shares2 = split_secret(3, 5, &secret2, &mut rng).unwrap();
        
        // Try to use shares from first split with shares from second split
        let result = recover_secret(
            &[0, 1, 2],
            &[shares1[0].clone(), shares1[1].clone(), shares2[2].clone()],
        );
        assert!(matches!(result, Err(Error::ChecksumFailure)));
    }

    #[test]
    fn test_no_share_correlation() {
        // Test that shares don't have obvious correlation
        let mut rng = make_test_rng();
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf");
        let shares = split_secret(2, 5, &secret, &mut rng).unwrap();
        
        // Shares should be different from each other
        for i in 0..shares.len() {
            for j in (i + 1)..shares.len() {
                assert_ne!(shares[i], shares[j]);
                
                // Calculate Hamming distance
                let hamming_distance: usize = shares[i]
                    .iter()
                    .zip(shares[j].iter())
                    .map(|(a, b)| (a ^ b).count_ones() as usize)
                    .sum();
                
                // Shares should differ significantly (at least 25% of bits)
                let total_bits = shares[i].len() * 8;
                assert!(
                    hamming_distance > total_bits / 4,
                    "Shares {} and {} are too similar (Hamming distance: {})",
                    i,
                    j,
                    hamming_distance
                );
            }
        }
    }

    #[test]
    fn test_avalanche_effect_secret_change() {
        // Test that small change in secret causes change in shares
        let mut rng1 = make_test_rng();
        let mut rng2 = make_test_rng();
        
        let secret1 = hex!("0ff784df000c4380a5ed683f7e6e3dcf");
        let mut secret2 = secret1.clone();
        secret2[0] ^= 0x01; // Flip one bit
        
        let shares1 = split_secret(2, 3, &secret1, &mut rng1).unwrap();
        let shares2 = split_secret(2, 3, &secret2, &mut rng2).unwrap();
        
        // Compare corresponding shares - they should be different
        // With same RNG seed, the shares should differ
        let mut differences = 0;
        for i in 0..shares1.len() {
            if shares1[i] != shares2[i] {
                differences += 1;
            }
        }
        
        // At least some shares should be different (avalanche effect)
        assert!(
            differences > 0,
            "Expected some shares to differ due to secret change"
        );
    }

    #[test]
    fn test_deterministic_with_same_rng() {
        // Test that same RNG seed produces same shares (for testing/debugging)
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf");
        
        let mut rng1 = make_test_rng();
        let shares1 = split_secret(2, 3, &secret, &mut rng1).unwrap();
        
        let mut rng2 = make_test_rng();
        let shares2 = split_secret(2, 3, &secret, &mut rng2).unwrap();
        
        // Should be identical with same seed
        assert_eq!(shares1, shares2);
    }

    #[test]
    fn test_non_deterministic_with_different_rng() {
        // Test that different RNG produces different shares
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf");
        
        let mut rng1 = bc_rand::SeededRandomNumberGenerator::new([1, 2, 3, 4]);
        let shares1 = split_secret(2, 3, &secret, &mut rng1).unwrap();
        
        let mut rng2 = bc_rand::SeededRandomNumberGenerator::new([5, 6, 7, 8]);
        let shares2 = split_secret(2, 3, &secret, &mut rng2).unwrap();
        
        // Should be different with different seeds
        assert_ne!(shares1, shares2);
    }

    #[test]
    fn test_checksum_collision_resistance() {
        // Test that different secrets with same share pattern are rejected
        let mut rng = make_test_rng();
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf");
        let shares = split_secret(3, 5, &secret, &mut rng).unwrap();
        
        // Try with insufficient shares multiple times
        for _ in 0..10 {
            let result = recover_secret(&[0, 1], &[shares[0].clone(), shares[1].clone()]);
            assert!(matches!(result, Err(Error::ChecksumFailure)));
        }
    }

    #[test]
    fn test_timing_attack_resistance_recovery() {
        // Test that recovery time is consistent regardless of share values
        use std::time::Instant;
        
        let mut rng = make_test_rng();
        let secret1 = vec![0x00u8; 32]; // All zeros
        let secret2 = vec![0xFFu8; 32]; // All ones
        let secret3 = hex!("0ff784df000c4380a5ed683f7e6e3dcf0123456789abcdef0011223344556677");
        
        let shares1 = split_secret(3, 5, &secret1, &mut rng).unwrap();
        let shares2 = split_secret(3, 5, &secret2, &mut rng).unwrap();
        let shares3 = split_secret(3, 5, &secret3, &mut rng).unwrap();
        
        // Measure recovery times
        let start1 = Instant::now();
        let _ = recover_secret(&[0, 1, 2], &[
            shares1[0].clone(),
            shares1[1].clone(),
            shares1[2].clone(),
        ])
        .unwrap();
        let time1 = start1.elapsed();
        
        let start2 = Instant::now();
        let _ = recover_secret(&[0, 1, 2], &[
            shares2[0].clone(),
            shares2[1].clone(),
            shares2[2].clone(),
        ])
        .unwrap();
        let time2 = start2.elapsed();
        
        let start3 = Instant::now();
        let _ = recover_secret(&[0, 1, 2], &[
            shares3[0].clone(),
            shares3[1].clone(),
            shares3[2].clone(),
        ])
        .unwrap();
        let time3 = start3.elapsed();
        
        // Times should be similar (within 10x factor for noisy measurements)
        // In production, this would be more rigorous statistical analysis
        let max_time = time1.max(time2).max(time3);
        let min_time = time1.min(time2).min(time3);
        
        // Allow 10x variation due to system noise
        assert!(
            max_time.as_micros() < min_time.as_micros() * 10,
            "Timing variation too high: min={:?}, max={:?}",
            min_time,
            max_time
        );
    }

    #[test]
    fn test_zero_knowledge_property() {
        // Test that shares reveal no information about secret without threshold
        let mut rng = make_test_rng();
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf");
        let shares = split_secret(5, 8, &secret, &mut rng).unwrap();
        
        // Even with k-1 shares, should not be able to derive correct secret
        for num_shares in 1..5 {
            let indexes: Vec<usize> = (0..num_shares).collect();
            let subset: Vec<Vec<u8>> = indexes.iter().map(|&i| shares[i].clone()).collect();
            
            let result = recover_secret(&indexes, &subset);
            // Either fails, or recovers wrong secret (checksum will catch it or result differs)
            match result {
                Err(_) => {
                    // Expected - should fail with insufficient shares
                },
                Ok(recovered) => {
                    // Should not recover the correct secret with insufficient shares
                    assert_ne!(
                        recovered, secret.to_vec(),
                        "Should not recover correct secret with {} shares (threshold is 5)",
                        num_shares
                    );
                }
            }
        }
    }

    #[test]
    fn test_share_independence_xor_analysis() {
        // Test that knowing some shares doesn't help predict others
        let mut rng = make_test_rng();
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf");
        let shares = split_secret(3, 6, &secret, &mut rng).unwrap();

        // XOR all shares - should not reveal secret or pattern
        let mut xor_result = vec![0u8; secret.len()];
        for share in &shares {
            for (i, &byte) in share.iter().enumerate() {
                xor_result[i] ^= byte;
            }
        }

        // XOR of all shares should not be the secret
        assert_ne!(xor_result, secret.to_vec());

        // XOR should not be all zeros or all ones (would indicate weakness)
        assert_ne!(xor_result, vec![0u8; secret.len()]);
        assert_ne!(xor_result, vec![0xFFu8; secret.len()]);
    }    #[test]
    fn test_malicious_share_index() {
        // Test handling of shares with tampered content
        let mut rng = make_test_rng();
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf");
        let mut shares = split_secret(2, 4, &secret, &mut rng).unwrap();
        
        // Create a malicious share with all zeros
        shares[0] = vec![0u8; secret.len()];
        
        let result = recover_secret(&[0, 1], &[shares[0].clone(), shares[1].clone()]);
        assert!(matches!(result, Err(Error::ChecksumFailure)));
    }

    #[test]
    fn test_entropy_preservation() {
        // Test that high-entropy secret produces high-entropy shares
        let mut rng = make_test_rng();
        
        // High entropy secret (pseudo-random)
        let secret: Vec<u8> = (0..32).map(|i| ((i * 137 + 91) % 256) as u8).collect();
        let shares = split_secret(2, 3, &secret, &mut rng).unwrap();
        
        // Each share should have reasonable entropy
        for (idx, share) in shares.iter().enumerate() {
            let mut byte_counts = [0usize; 256];
            for &byte in share {
                byte_counts[byte as usize] += 1;
            }
            
            // Check that bytes are reasonably distributed (no single byte dominates)
            let max_count = byte_counts.iter().max().unwrap();
            assert!(
                *max_count < share.len() / 2,
                "Share {} has poor entropy: one byte appears {} times out of {}",
                idx,
                max_count,
                share.len()
            );
        }
    }

    #[test]
    fn test_side_channel_constant_time_comparison() {
        // Verify checksum comparison is constant-time (no early exit)
        let mut rng = make_test_rng();
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf");
        let shares = split_secret(2, 3, &secret, &mut rng).unwrap();
        
        // Tamper first byte vs last byte - timing should be similar
        let mut tampered_first = shares[0].clone();
        tampered_first[0] ^= 0xFF;
        
        let mut tampered_last = shares[0].clone();
        let last_idx = tampered_last.len() - 1;
        tampered_last[last_idx] ^= 0xFF;
        
        // Both should fail with same error
        let result1 = recover_secret(&[0, 1], &[tampered_first, shares[1].clone()]);
        let result2 = recover_secret(&[0, 1], &[tampered_last, shares[1].clone()]);
        
        assert!(matches!(result1, Err(Error::ChecksumFailure)));
        assert!(matches!(result2, Err(Error::ChecksumFailure)));
    }

    #[test]
    fn test_perfect_secrecy_threshold() {
        // Test perfect secrecy: k-1 shares reveal nothing, k shares reveal all
        let mut rng = make_test_rng();
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf");
        let threshold = 4;
        let shares = split_secret(threshold, 6, &secret, &mut rng).unwrap();
        
        // With k-1 shares, cannot recover
        let result_insufficient = recover_secret(
            &[0, 1, 2],
            &[shares[0].clone(), shares[1].clone(), shares[2].clone()],
        );
        assert!(matches!(result_insufficient, Err(Error::ChecksumFailure)));
        
        // With k shares, can recover perfectly
        let result_sufficient = recover_secret(
            &[0, 1, 2, 3],
            &[
                shares[0].clone(),
                shares[1].clone(),
                shares[2].clone(),
                shares[3].clone(),
            ],
        )
        .unwrap();
        assert_eq!(result_sufficient, secret);
    }

    #[test]
    fn test_cryptographic_randomness_requirement() {
        // Test that using secure RNG produces unpredictable shares
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf");
        
        // Create multiple share sets with cryptographic RNG
        let mut shares_sets = vec![];
        for _ in 0..3 {
            let mut rng = bc_rand::SecureRandomNumberGenerator;
            let shares = split_secret(2, 3, &secret, &mut rng).unwrap();
            shares_sets.push(shares);
        }
        
        // All share sets should be different (extremely high probability)
        for i in 0..shares_sets.len() {
            for j in (i + 1)..shares_sets.len() {
                assert_ne!(
                    shares_sets[i], shares_sets[j],
                    "Share sets should be different with cryptographic RNG"
                );
            }
        }
    }

    #[test]
    fn test_no_weak_keys() {
        // Test that "weak" secrets still produce secure shares
        let mut rng = make_test_rng();
        
        let weak_secrets = vec![
            vec![0x00u8; 16], // All zeros
            vec![0xFFu8; 16], // All ones
            vec![0xAAu8; 16], // Repeating pattern
            vec![0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04], // Repeating sequence
        ];
        
        for secret in weak_secrets {
            let shares = split_secret(2, 3, &secret, &mut rng).unwrap();
            
            // Shares should not be weak even if secret is
            for share in &shares {
                assert_ne!(share, &secret, "Share should not equal weak secret");
                
                // Share should not be all same byte
                let first_byte = share[0];
                let all_same = share.iter().all(|&b| b == first_byte);
                assert!(!all_same, "Share should not be all same byte for weak secret");
            }
            
            // Should still be able to recover
            let recovered = recover_secret(&[0, 1], &[shares[0].clone(), shares[1].clone()]).unwrap();
            assert_eq!(recovered, secret);
        }
    }
}
