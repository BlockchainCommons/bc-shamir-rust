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

/*
```c
//////////////////////////////////////////////////
// shamir sharing
int32_t split_secret(
    uint8_t threshold,
    uint8_t share_count,
    const uint8_t *secret,
    uint32_t secret_length,
    uint8_t *result,
    void* ctx,
    void (*random_generator)(uint8_t *, size_t, void*)
) {
    int32_t err = validate_parameters(threshold, share_count, secret_length);
    if(err) {
        return err;
    }

    if(threshold == 1) {
        // just return share_count copies of the secret
        uint8_t *share = result;
        for(uint8_t i=0; i< share_count; ++i, share += secret_length) {
            for(uint8_t j=0; j<secret_length; ++j) {
                share[j] = secret[j];
            }
        }
        return share_count;
    } else {
        uint8_t digest[secret_length];
        uint8_t x[16];
        const uint8_t *y[16];
        uint8_t n = 0;
        uint8_t *share = result;

        for(uint8_t i=0; i< threshold-2; ++i, share+=secret_length) {
            random_generator(share, secret_length, ctx);
            x[n] = i;
            y[n] = share;
            n+=1;
        }

        // generate secret_length - 4 bytes worth of random data
        random_generator(digest+4, secret_length-4, ctx);
        // put 4 bytes of digest at the top of the digest array
        create_digest(digest+4, secret_length-4, secret, secret_length, digest);
        x[n] = DIGEST_INDEX;
        y[n] = digest;
        n+=1;

        x[n] = SECRET_INDEX;
        y[n] = secret;
        n+=1;

        for(uint8_t i=threshold -2; i<share_count; ++i, share += secret_length) {
            if(interpolate(n, x, secret_length, y, i, share) < 0) {
                return SHAMIR_ERROR_INTERPOLATION_FAILURE;
            }
        }

        memzero(digest, sizeof(digest));
        memzero(x, sizeof(x));
        memzero(y, sizeof(y));
    }
    return share_count;
}
```
 */

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
        let mut x = [0u8; 16];
        let mut y = vec![vec![0u8; SHAMIR_MAX_SECRET_SIZE]; 16];
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
        digest[..4].copy_from_slice(&d);
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
