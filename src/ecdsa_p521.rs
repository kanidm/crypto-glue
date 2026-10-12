use ecdsa::{DigestAlgorithm, Signature, SignatureBytes, SigningKey, VerifyingKey};
use elliptic_curve::{
    FieldBytes, PublicKey, SecretKey,
    point::AffinePoint,
    sec1::{FromSec1Point, Sec1Point},
};
use p521::{NistP521, ecdsa::DerSignature};

pub type EcdsaP521Digest = <NistP521 as DigestAlgorithm>::Digest;

pub type EcdsaP521PrivateKey = SecretKey<NistP521>;

pub type EcdsaP521FieldBytes = FieldBytes<NistP521>;
pub type EcdsaP521AffinePoint = AffinePoint<NistP521>;

pub type EcdsaP521PublicKey = PublicKey<NistP521>;

// pub type EcdsaP521PublicCoordinate = GenericArray<u8, U32>;
pub type EcdsaP521PublicSec1Point = Sec1Point<NistP521>;

pub type EcdsaP521SigningKey = SigningKey<NistP521>;
pub type EcdsaP521VerifyingKey = VerifyingKey<NistP521>;

pub type EcdsaP521Signature = Signature<NistP521>;
pub type EcdsaP521DerSignature = DerSignature;
pub type EcdsaP521SignatureBytes = SignatureBytes<NistP521>;

pub fn new_key() -> EcdsaP521PrivateKey {
    use crypto_common::Generate;
    EcdsaP521PrivateKey::generate()
}

pub fn from_coords_raw(x: &[u8], y: &[u8]) -> Option<EcdsaP521PublicKey> {
    let mut field_x = EcdsaP521FieldBytes::default();
    if x.len() != field_x.len() {
        return None;
    }

    let mut field_y = EcdsaP521FieldBytes::default();
    if y.len() != field_y.len() {
        return None;
    }

    field_x.copy_from_slice(x);
    field_y.copy_from_slice(y);

    let ep = EcdsaP521PublicSec1Point::from_affine_coordinates(&field_x, &field_y, false);

    EcdsaP521PublicKey::from_sec1_point(&ep).into_option()
}
