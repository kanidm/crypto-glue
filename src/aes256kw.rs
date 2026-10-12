use hybrid_array::{Array, sizes::U40};

pub use crypto_common::KeyInit;

pub type Aes256Kw = aes_kw::KwAes256;

pub type Aes256KwWrapped = Array<u8, U40>;
