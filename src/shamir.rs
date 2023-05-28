use bc_crypto::{hash::hmac_sha256, RandomNumberGenerator, memzero, memzero_vec_vec_u8};

use crate::{
    MAX_SHARE_COUNT,
    MAX_SECRET_LEN,
    MIN_SECRET_LEN,
    ShamirError,
    interpolate::interpolate,
};

const SECRET_INDEX: u8 = 255;
const DIGEST_INDEX: u8 = 254;

fn create_digest(random_data: &[u8], shared_secret: &[u8]) -> [u8; 32] {
    hmac_sha256(random_data, shared_secret)
}

fn validate_parameters(threshold: usize, share_count: usize, secret_length: usize) -> Result<(), ShamirError> {
    if share_count > MAX_SHARE_COUNT {
        return Err(ShamirError::TooManyShares);
    } else if threshold < 1 || threshold > share_count {
        return Err(ShamirError::InvalidThreshold);
    } else if secret_length > MAX_SECRET_LEN {
        return Err(ShamirError::SecretTooLong);
    } else if secret_length < MIN_SECRET_LEN {
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

pub fn recover_secret<T>(indexes: &[usize], shares: &[T]) -> Result<Vec<u8>, ShamirError>
    where T: AsRef<[u8]>
{
    let threshold = shares.len();
    if threshold == 0 || indexes.len() != threshold {
        return Err(ShamirError::InvalidThreshold);
    }
    let share_length = shares[0].as_ref().len();
    validate_parameters(threshold, threshold, share_length)?;

    shares.iter().all(|share| share.as_ref().len() == share_length)
        .then_some(()).ok_or(ShamirError::SharesUnequalLength)?;

    if threshold == 1 {
        Ok(shares[0].as_ref().to_vec())
    } else {
        let indexes = indexes.iter().map(|x| *x as u8).collect::<Vec<_>>();
        let mut digest = interpolate(threshold, &indexes, share_length, shares, DIGEST_INDEX)?;
        let secret = interpolate(threshold, &indexes, share_length, shares, SECRET_INDEX)?;
        let mut verify = create_digest(&digest[4..], &secret);

        let mut valid = true;
        for i in 0..4 {
            valid &= digest[i] == verify[i];
        }
        memzero(&mut digest);
        memzero(&mut verify);

        if !valid {
            return Err(ShamirError::ChecksumFailure);
        }

        Ok(secret)
    }
}
