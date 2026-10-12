use ecdsa::{DigestAlgorithm, Signature, SignatureBytes, SigningKey, VerifyingKey};
use elliptic_curve::{
    FieldBytes, PublicKey, SecretKey,
    point::AffinePoint,
    scalar::NonZeroScalar,
    sec1::{FromSec1Point, Sec1Point},
};
use hybrid_array::{Array, sizes::U32};
use p256::{NistP256, ecdsa::DerSignature};

pub type EcdsaP256Digest = <NistP256 as DigestAlgorithm>::Digest;

pub type EcdsaP256PrivateKey = SecretKey<NistP256>;
pub type EcdsaP256NonZeroScalar = NonZeroScalar<NistP256>;

pub type EcdsaP256FieldBytes = FieldBytes<NistP256>;
pub type EcdsaP256AffinePoint = AffinePoint<NistP256>;

pub type EcdsaP256PublicKey = PublicKey<NistP256>;

pub type EcdsaP256PublicCoordinate = Array<u8, U32>;
pub type EcdsaP256PublicSec1Point = Sec1Point<NistP256>;

pub type EcdsaP256SigningKey = SigningKey<NistP256>;
pub type EcdsaP256VerifyingKey = VerifyingKey<NistP256>;

pub type EcdsaP256Signature = Signature<NistP256>;
pub type EcdsaP256DerSignature = DerSignature;
pub type EcdsaP256SignatureBytes = SignatureBytes<NistP256>;

pub fn new_key() -> EcdsaP256PrivateKey {
    use crypto_common::Generate;

    EcdsaP256PrivateKey::generate()
}

pub fn from_coords_raw(x: &[u8], y: &[u8]) -> Option<EcdsaP256PublicKey> {
    let mut field_x = EcdsaP256FieldBytes::default();
    if x.len() != field_x.len() {
        return None;
    }

    let mut field_y = EcdsaP256FieldBytes::default();
    if y.len() != field_y.len() {
        return None;
    }

    field_x.copy_from_slice(x);
    field_y.copy_from_slice(y);

    let ep = EcdsaP256PublicSec1Point::from_affine_coordinates(&field_x, &field_y, false);

    EcdsaP256PublicKey::from_sec1_point(&ep).into_option()
}
