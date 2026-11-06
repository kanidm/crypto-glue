use elliptic_curve::{
    FieldBytes, PublicKey,
    ecdh::{EphemeralSecret, SharedSecret},
    sec1::Sec1Point,
};
use hkdf::Hkdf;
use p256::NistP256;
use sha2::Sha256;

pub type EcdhP256EphemeralSecret = EphemeralSecret<NistP256>;
pub type EcdhP256SharedSecret = SharedSecret<NistP256>;
pub type EcdhP256PublicKey = PublicKey<NistP256>;
pub type EcdhP256PublicSec1Point = Sec1Point<NistP256>;
pub type EcdhP256FieldBytes = FieldBytes<NistP256>;

pub type EcdhP256Hkdf = Hkdf<Sha256>;

pub type EcdhP256Digest = Sha256;

pub fn new_secret() -> EcdhP256EphemeralSecret {
    use crypto_common::Generate;
    EcdhP256EphemeralSecret::generate()
}
