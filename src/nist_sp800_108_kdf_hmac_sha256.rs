use crate::traits::Zeroizing;
use crypto_common::KeySizeUser;
use digest::consts::*;
use hmac::Hmac;
use kbkdf::{Counter, Kbkdf, Params};
use sha2::Sha256;

struct MockOutput;

impl KeySizeUser for MockOutput {
    type KeySize = U32;
}

type HmacSha256 = Hmac<Sha256>;

pub fn derive_key_aes256(
    key_in: &[u8],
    label: &[u8],
    context: &[u8],
) -> Option<Zeroizing<Vec<u8>>> {
    let counter = Counter::<HmacSha256, MockOutput>::default();
    let params = Params::builder(key_in)
        .with_label(label)
        .with_context(context)
        .use_l(true)
        .use_separator(true)
        .use_counter(true)
        .build();
    let key = counter.derive(params).ok()?;

    let mut output = Zeroizing::new(vec![0; MockOutput::key_size()]);
    output.copy_from_slice(key.as_slice());
    Some(output)
}
