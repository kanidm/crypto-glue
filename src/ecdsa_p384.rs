use ecdsa::{DigestAlgorithm, Signature, SignatureBytes, SigningKey, VerifyingKey};
use elliptic_curve::{
    FieldBytes, PublicKey, SecretKey,
    point::AffinePoint,
    sec1::{FromSec1Point, Sec1Point},
};
use p384::{NistP384, ecdsa::DerSignature};
// use sha2::digest::consts::U32;

pub type EcdsaP384Digest = <NistP384 as DigestAlgorithm>::Digest;

pub type EcdsaP384PrivateKey = SecretKey<NistP384>;

pub type EcdsaP384FieldBytes = FieldBytes<NistP384>;
pub type EcdsaP384AffinePoint = AffinePoint<NistP384>;

pub type EcdsaP384PublicKey = PublicKey<NistP384>;

// pub type EcdsaP384PublicCoordinate = GenericArray<u8, U32>;
pub type EcdsaP384PublicSec1Point = Sec1Point<NistP384>;

pub type EcdsaP384SigningKey = SigningKey<NistP384>;
pub type EcdsaP384VerifyingKey = VerifyingKey<NistP384>;

pub type EcdsaP384Signature = Signature<NistP384>;
pub type EcdsaP384DerSignature = DerSignature;
pub type EcdsaP384SignatureBytes = SignatureBytes<NistP384>;

pub fn new_key() -> EcdsaP384PrivateKey {
    use crypto_common::Generate;
    EcdsaP384PrivateKey::generate()
}

pub fn from_coords_raw(x: &[u8], y: &[u8]) -> Option<EcdsaP384PublicKey> {
    let mut field_x = EcdsaP384FieldBytes::default();
    if x.len() != field_x.len() {
        return None;
    }

    let mut field_y = EcdsaP384FieldBytes::default();
    if y.len() != field_y.len() {
        return None;
    }

    field_x.copy_from_slice(x);
    field_y.copy_from_slice(y);

    let ep = EcdsaP384PublicSec1Point::from_affine_coordinates(&field_x, &field_y, false);

    EcdsaP384PublicKey::from_sec1_point(&ep).into_option()
}
