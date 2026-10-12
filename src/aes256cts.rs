use aes::cipher::{Array, consts::U16};

pub use crate::aes256::Aes256Key;
pub use aes::cipher::{BlockModeDecrypt, BlockModeEncrypt, InnerIvInit, KeyIvInit};
pub use cts::{Decrypt as CtsDecrypt, Encrypt as CtsEncrypt};

pub type Aes256CtsEnc = cts::CbcCs3<aes::Aes256>;
pub type Aes256CtsDec = cts::CbcCs3<aes::Aes256>;

pub type Aes256CtsIv = Array<u8, U16>;

pub fn new_iv() -> Aes256CtsIv {
    use crypto_common::Generate;
    Aes256CtsIv::generate()
}
