use hkdf::Hkdf;
use sha2::Sha256;

pub type HkdfSha256 = Hkdf<Sha256>;
