use hybrid_array::{Array, sizes::U24};

pub use crypto_common::KeyInit;

pub type Aes128Kw = aes_kw::KwAes128;

pub type Aes128KwWrapped = Array<u8, U24>;
