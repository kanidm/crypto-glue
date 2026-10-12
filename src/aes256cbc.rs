use crate::hmac_s256::{HmacSha256, HmacSha256Output};
use aes::cipher::{Array, consts::U16};

pub use crate::aes256::Aes256Key;
pub use aes::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit, block_padding};

pub type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
pub type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

pub type Aes256CbcIv = Array<u8, U16>;

pub fn new_iv() -> Aes256CbcIv {
    use crypto_common::Generate;
    Aes256CbcIv::generate()
}

pub fn enc<P>(
    key: &Aes256Key,
    data: &[u8],
) -> Result<(HmacSha256Output, Aes256CbcIv, Vec<u8>), crypto_common::InvalidLength>
where
    P: block_padding::Padding,
{
    use cipher::BlockModeEncrypt;
    use cipher::KeyInit;
    use hmac::Mac;

    let iv = new_iv();
    let enc = Aes256CbcEnc::new(key, &iv);

    let ciphertext = enc.encrypt_padded_vec::<P>(data);

    let mut hmac = HmacSha256::new_from_slice(key.as_slice())?;
    hmac.update(&ciphertext);
    let mac = hmac.finalize();

    Ok((mac, iv, ciphertext))
}

pub fn dec<P>(
    key: &Aes256Key,
    mac: &HmacSha256Output,
    iv: &Aes256CbcIv,
    ciphertext: &[u8],
) -> Option<Vec<u8>>
where
    P: block_padding::Padding,
{
    use cipher::BlockModeDecrypt;
    use cipher::KeyInit;
    use hmac::Mac;

    let mut hmac = HmacSha256::new_from_slice(key.as_slice()).ok()?;
    hmac.update(ciphertext);
    let check_mac = hmac.finalize();

    if check_mac != *mac {
        return None;
    }

    let dec = Aes256CbcDec::new(key, iv);

    let plaintext = dec.decrypt_padded_vec::<P>(ciphertext).ok()?;

    Some(plaintext)
}
