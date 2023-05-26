use bc_crypto::{hash::hmac_sha256, RandomNumberGenerator};

use crate::{
    ShamirError,
    constants::{
        SHAMIR_MAX_SHARE_COUNT,
        SHAMIR_MAX_SECRET_SIZE,
        SHAMIR_MIN_SECRET_SIZE
    },
    interpolate::interpolate,
    hazmat::{
        memzero,
        memzero_vec_vec_u8
    }
};

const SECRET_INDEX: u8 = 255;
const DIGEST_INDEX: u8 = 254;

fn create_digest(random_data: &[u8], shared_secret: &[u8]) -> [u8; 32] {
    hmac_sha256(random_data, shared_secret)
}

fn validate_parameters(threshold: usize, share_count: usize, secret_length: usize) -> Result<(), ShamirError> {
    if share_count > SHAMIR_MAX_SHARE_COUNT {
        return Err(ShamirError::TooManyShares);
    } else if threshold < 1 || threshold > share_count {
        return Err(ShamirError::InvalidThreshold);
    } else if secret_length > SHAMIR_MAX_SECRET_SIZE {
        return Err(ShamirError::SecretTooLong);
    } else if secret_length < SHAMIR_MIN_SECRET_SIZE {
        return Err(ShamirError::SecretTooShort);
    } else if secret_length & 1 != 0 {
        return Err(ShamirError::SecretNotEvenLen);
    }
    Ok(())
}

pub fn split_secret(
    threshold: usize,
    share_count: usize,
    secret: &[u8],
    random_generator: &mut impl RandomNumberGenerator
) -> Result<Vec<Vec<u8>>, ShamirError> {
    validate_parameters(threshold, share_count, secret.len())?;

    if threshold == 1 {
        // just return share_count copies of the secret
        let mut result = vec![vec![0u8; secret.len()]; share_count];
        for share in &mut result {
            share.copy_from_slice(secret);
        }
        Ok(result)
    } else {
        let mut x = vec![0u8; share_count];
        let mut y = vec![vec![0u8; secret.len()]; share_count];
        let mut n = 0;
        let mut result = vec![vec![0u8; secret.len()]; share_count];

        result.iter_mut().enumerate().take(threshold - 2).for_each(|(index, result_item)| {
            random_generator.fill_random_data(result_item);
            x[n] = index as u8;
            y[n].copy_from_slice(result_item);
            n += 1;
        });

        // generate secret_length - 4 bytes worth of random data
        let mut digest = vec![0u8; secret.len()];
        random_generator.fill_random_data(&mut digest[4..]);
        // put 4 bytes of digest at the top of the digest array
        let d = create_digest(&digest[4..], secret);
        digest[..4].copy_from_slice(&d[..4]);
        x[n] = DIGEST_INDEX;
        y[n].copy_from_slice(&digest);
        n += 1;

        x[n] = SECRET_INDEX;
        y[n].copy_from_slice(secret);
        n += 1;

        result.iter_mut().enumerate().take(share_count).skip(threshold - 2).try_for_each(|(index, result_item)| {
            let v = interpolate(n, &x, secret.len(), &y, index as u8)?;
            result_item.copy_from_slice(&v);
            Ok(())
        })?;

        // clean up stack
        memzero(&mut digest);
        memzero(&mut x);
        memzero_vec_vec_u8(&mut y);

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    struct FakeRandomNumberGenerator;

    impl RandomNumberGenerator for FakeRandomNumberGenerator {
        fn next_u64(&mut self) -> u64 {
            unimplemented!()
        }

        fn random_data(&mut self, size: usize) -> Vec<u8> {
            let mut b = vec![0u8; size];
            self.fill_random_data(&mut b);
            b
        }

        fn fill_random_data(&mut self, data: &mut [u8]) {
            let mut b = 0u8;
            data.iter_mut().for_each(|x| {
                *x = b;
                b = b.wrapping_add(17);
            });
        }
    }

    #[test]
    fn test_split_secret_3_5() {
        let mut rng = FakeRandomNumberGenerator;
        let secret = hex!("0ff784df000c4380a5ed683f7e6e3dcf");
        //println!("secret: {}", hex::encode(secret));
        let shares = split_secret(3, 5, &secret, &mut rng).unwrap();
        assert_eq!(shares.len(), 5);
        //shares.iter().enumerate().for_each(|(index, share)| println!("{}: {}", index, hex::encode(share)));
        assert_eq!(shares[0], hex!("00112233445566778899aabbccddeeff"));
        assert_eq!(shares[1], hex!("d43099fe444807c46921a4f33a2a798b"));
        assert_eq!(shares[2], hex!("d9ad4e3bec2e1a7485698823abf05d36"));
        assert_eq!(shares[3], hex!("0d8cf5f6ec337bc764d1866b5d07ca42"));
        assert_eq!(shares[4], hex!("1aa7fe3199bc5092ef3816b074cabdf2"));
    }

    #[test]
    fn test_split_secret_2_7() {
        let mut rng = FakeRandomNumberGenerator;
        let secret = hex!("204188bfa6b440a1bdfd6753ff55a8241e07af5c5be943db917e3efabc184b1a");
        //println!("secret: {}", hex::encode(secret));
        let shares = split_secret(2, 7, &secret, &mut rng).unwrap();
        assert_eq!(shares.len(), 7);
        //shares.iter().enumerate().for_each(|(index, share)| println!("{}: {}", index, hex::encode(share)));
        assert_eq!(shares[0], hex!("2dcd14c2252dc8489af3985030e74d5a48e8eff1478ab86e65b43869bf39d556"));
        assert_eq!(shares[1], hex!("a1dfdd798388aada635b9974472b4fc59a32ae520c42c9f6a0af70149b882487"));
        assert_eq!(shares[2], hex!("2ee99daf727c0c7773b89a18de64497ff7476dacd1015a45f482a893f7402cef"));
        assert_eq!(shares[3], hex!("a2fb5414d4d96ee58a109b3ca9a84be0259d2c0f9ac92bdd3199e0eed3f1dd3e"));
        assert_eq!(shares[4], hex!("2b851d188b8f5b3653659cc0f7fa45102dadf04b708767385cd803862fcb3c3f"));
        assert_eq!(shares[5], hex!("a797d4a32d2a39a4aacd9de48036478fff77b1e83b4f16a099c34bfb0b7acdee"));
        assert_eq!(shares[6], hex!("28a19475dcde9f09ba2e9e881979413592027216e60c8513cdee937c67b2c586"));
    }
}
