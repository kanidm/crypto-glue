use rsa::{
    RsaPrivateKey, RsaPublicKey,
    pkcs1v15::{Signature, SigningKey, VerifyingKey},
};

pub use rand;
pub use rsa::{BoxedUint as BigUint, Oaep, pkcs1v15};
pub use sha2::{Sha256, Sha384};

pub const MIN_BITS: usize = 2048;

pub type RS256PrivateKey = RsaPrivateKey;
pub type RS256PublicKey = RsaPublicKey;
pub type RS256Signature = Signature;
pub type RS256Digest = Sha256;
pub type RS256VerifyingKey = VerifyingKey<Sha256>;
pub type RS256SigningKey = SigningKey<Sha256>;

pub type RS384Digest = Sha384;
pub type RS384VerifyingKey = VerifyingKey<Sha384>;
pub type RS384SigningKey = SigningKey<Sha384>;

pub fn new_key(bits: usize) -> rsa::errors::Result<RsaPrivateKey> {
    let bits = std::cmp::max(bits, MIN_BITS);
    let mut rng = rand::rng();
    RsaPrivateKey::new(&mut rng, bits)
}

pub fn oaep_sha256_encrypt(public_key: &RsaPublicKey, data: &[u8]) -> rsa::errors::Result<Vec<u8>> {
    let mut rng = rand::rng();
    let padding = Oaep::<Sha256>::new();
    public_key.encrypt(&mut rng, padding, data)
}

pub fn oaep_sha256_decrypt(
    private_key: &RsaPrivateKey,
    ciphertext: &[u8],
) -> rsa::errors::Result<Vec<u8>> {
    let padding = Oaep::<Sha256>::new();
    private_key.decrypt(padding, ciphertext)
}
