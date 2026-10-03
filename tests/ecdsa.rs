use crypto_glue::{ecdsa_p256::*, traits::*};

#[cfg(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none")))]
use wasm_bindgen_test::*;
#[cfg(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none")))]
wasm_bindgen_test_configure!(run_in_browser);

#[test]
#[cfg_attr(
    all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none")),
    wasm_bindgen_test
)]
fn ecdsa_p256_basic() {
    let priv_key = new_key();

    let pub_key = priv_key.public_key();

    let signer = EcdsaP256SigningKey::from(&priv_key);
    let verifier = EcdsaP256VerifyingKey::from(&pub_key);

    // Can either sign data directly, using the correct associated hash type.
    let data = [0, 1, 2, 3, 4, 5, 6, 7];

    let sig: EcdsaP256Signature = signer.try_sign(&data).expect("Failed to sign data");

    assert!(verifier.verify(&data, &sig).is_ok());

    // Or you can build the digest content directly, based on the type of the C::Digest value.
    let sig: EcdsaP256Signature = signer
        .try_sign_digest(|digest: &mut EcdsaP256Digest| {
            digest.update(data);
            Ok(())
        })
        .expect("Failed to sign digest");
    assert!(verifier.verify(&data, &sig).is_ok());
}
