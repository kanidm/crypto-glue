pub use argon2;
pub use hex;
pub use rand;
pub use spki;
pub use zeroize;

pub mod prelude {}

#[cfg(test)]
mod test_ca;

pub mod traits {
    pub use elliptic_curve::sec1::FromEncodedPoint;
    pub use pkcs8::{
        DecodePrivateKey as Pkcs8DecodePrivateKey, EncodePrivateKey as Pkcs8EncodePrivateKey,
    };
    pub use rsa::pkcs1::DecodeRsaPrivateKey as Pkcs1DecodeRsaPrivateKey;
    pub use rsa::signature::{
        DigestSigner, Keypair, RandomizedSigner, SignatureEncoding, Signer, Verifier,
    };
    pub use sha2::Digest;
    pub use spki::{
        DecodePublicKey as SpkiDecodePublicKey, EncodePublicKey as SpkiEncodePublicKey,
    };
    pub use zeroize::Zeroizing;
}

pub mod x509;

pub mod sha1 {
    use generic_array::GenericArray;
    use sha1::digest::consts::U20;

    pub use sha1::Sha1;

    pub type Sha1Output = GenericArray<u8, U20>;
}

pub mod s256 {
    use generic_array::GenericArray;
    use sha2::digest::consts::U32;

    pub use sha2::Sha256;

    pub type Sha256Output = GenericArray<u8, U32>;
}

pub mod hmac_s256 {
    use crypto_common::Key;
    use crypto_common::Output;

    use hmac::Hmac;
    use sha2::digest::CtOutput;
    use sha2::Sha256;
    use zeroize::Zeroizing;

    pub use hmac::Mac;

    pub type HmacSha256 = Hmac<Sha256>;

    pub type HmacSha256Key = Zeroizing<Key<Hmac<Sha256>>>;

    pub type HmacSha256Output = CtOutput<HmacSha256>;

    pub type HmacSha256Bytes = Output<HmacSha256>;

    pub fn new_key() -> HmacSha256Key {
        use crypto_common::KeyInit;

        let mut rng = rand::thread_rng();
        HmacSha256::generate_key(&mut rng).into()
    }

    pub fn oneshot(key: &HmacSha256Key, data: &[u8]) -> HmacSha256Output {
        let mut hmac = HmacSha256::new(&key);
        hmac.update(data);
        hmac.finalize()
    }

    pub fn key_from_vec(bytes: Vec<u8>) -> Option<HmacSha256Key> {
        Key::<Hmac<Sha256>>::from_exact_iter(bytes.into_iter()).map(|key| key.into())
    }

    pub fn key_from_bytes(bytes: [u8; 64]) -> HmacSha256Key {
        Key::<Hmac<Sha256>>::from(bytes).into()
    }

    pub fn key_size() -> usize {
        use crypto_common::KeySizeUser;
        Hmac::<Sha256>::key_size()
    }
}

pub mod hmac_s512 {
    use crypto_common::Key;
    use crypto_common::Output;

    use hmac::Hmac;
    use sha2::digest::CtOutput;
    use sha2::Sha512;
    use zeroize::Zeroizing;

    pub use hmac::Mac;

    pub type HmacSha512 = Hmac<Sha512>;

    pub type HmacSha512Key = Zeroizing<Key<Hmac<Sha512>>>;

    pub type HmacSha512Output = CtOutput<HmacSha512>;

    pub type HmacSha512Bytes = Output<HmacSha512>;

    pub fn new_hmac_sha512_key() -> HmacSha512Key {
        use crypto_common::KeyInit;

        let mut rng = rand::thread_rng();
        HmacSha512::generate_key(&mut rng).into()
    }

    pub fn oneshot(key: &HmacSha512Key, data: &[u8]) -> HmacSha512Output {
        let mut hmac = HmacSha512::new(&key);
        hmac.update(data);
        hmac.finalize()
    }
}

pub mod aes256 {
    use aes;
    use crypto_common::Key;
    use crypto_common::KeyInit;
    use zeroize::Zeroizing;

    pub type Aes256Key = Zeroizing<Key<aes::Aes256>>;

    pub fn key_size() -> usize {
        use crypto_common::KeySizeUser;
        aes::Aes256::key_size()
    }

    pub fn key_from_vec(bytes: Vec<u8>) -> Option<Aes256Key> {
        Key::<aes::Aes256>::from_exact_iter(bytes.into_iter()).map(|key| key.into())
    }

    pub fn key_from_bytes(bytes: [u8; 32]) -> Aes256Key {
        Key::<aes::Aes256>::from(bytes).into()
    }

    pub fn new_key() -> Aes256Key {
        let mut rng = rand::thread_rng();
        aes::Aes256::generate_key(&mut rng).into()
    }
}

pub mod aes256gcm {
    use aes::cipher::consts::{U12, U16};
    use aes::Aes256;
    use aes_gcm::aead::AeadCore;
    use aes_gcm::AesGcm;
    use generic_array::GenericArray;

    pub use aes_gcm::aead::{Aead, AeadInPlace, Payload};
    pub use crypto_common::KeyInit;

    pub use crate::aes256::Aes256Key;

    // Same as  AesGcm<Aes256, U12, U16>;
    pub type Aes256Gcm = aes_gcm::Aes256Gcm;

    pub type Aes256GcmN16 = AesGcm<Aes256, U16, U16>;
    pub type Aes256GcmNonce16 = GenericArray<u8, U16>;

    pub type Aes256GcmNonce = GenericArray<u8, U12>;

    pub type Aes256GcmTag = GenericArray<u8, U16>;

    pub fn new_nonce() -> Aes256GcmNonce {
        let mut rng = rand::thread_rng();

        Aes256Gcm::generate_nonce(&mut rng)
    }
}

pub mod aes256cbc {
    use crate::hmac_s256::HmacSha256;
    use crate::hmac_s256::HmacSha256Output;
    use aes::cipher::consts::U16;
    use generic_array::GenericArray;

    pub use crate::aes256::Aes256Key;

    pub use aes::cipher::{block_padding, BlockDecryptMut, BlockEncryptMut, KeyIvInit};

    pub type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
    pub type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

    pub type Aes256CbcIv = GenericArray<u8, U16>;

    pub fn new_iv() -> Aes256CbcIv {
        let mut rng = rand::thread_rng();
        Aes256CbcEnc::generate_iv(&mut rng)
    }

    pub fn enc<P>(
        key: &Aes256Key,
        data: &[u8],
    ) -> Result<(HmacSha256Output, Aes256CbcIv, Vec<u8>), crypto_common::InvalidLength>
    where
        P: block_padding::Padding<<aes::Aes256 as crypto_common::BlockSizeUser>::BlockSize>,
    {
        use hmac::Mac;

        let iv = new_iv();
        let enc = Aes256CbcEnc::new(&key, &iv);

        let ciphertext = enc.encrypt_padded_vec_mut::<P>(data);

        let mut hmac = HmacSha256::new_from_slice(key.as_slice())?;
        hmac.update(&ciphertext);
        let mac = hmac.finalize();

        Ok((mac, iv, ciphertext))
    }

    pub fn dec<P>(
        key: &Aes256Key,
        mac: &HmacSha256Output,
        iv: &Aes256CbcIv,
        ciphertext: &Vec<u8>,
    ) -> Result<Vec<u8>, ()>
    where
        P: block_padding::Padding<<aes::Aes256 as crypto_common::BlockSizeUser>::BlockSize>,
    {
        use hmac::Mac;

        let mut hmac = HmacSha256::new_from_slice(key.as_slice()).map_err(|_| ())?;
        hmac.update(&ciphertext);
        let check_mac = hmac.finalize();

        if check_mac != *mac {
            return Err(());
        }

        let dec = Aes256CbcDec::new(&key, &iv);

        let plaintext = dec
            .decrypt_padded_vec_mut::<P>(&ciphertext)
            .map_err(|_| ())?;

        Ok(plaintext)
    }
}

pub mod aes256kw {
    use aes::cipher::consts::U40;
    use generic_array::GenericArray;

    pub use crypto_common::KeyInit;

    pub type Aes256Kw = aes_kw::KekAes256;

    pub type Aes256KwWrapped = GenericArray<u8, U40>;
}

pub mod rsa {
    use rsa::pkcs1v15::{Signature, SigningKey, VerifyingKey};
    use rsa::{RsaPrivateKey, RsaPublicKey};

    pub use rand;
    pub use rsa::BigUint;
    pub use rsa::{pkcs1v15, Oaep};
    pub use sha2::Sha256;

    pub const MIN_BITS: usize = 2048;

    pub type RS256PrivateKey = RsaPrivateKey;
    pub type RS256PublicKey = RsaPublicKey;
    pub type RS256Signature = Signature;
    pub type RS256Digest = Sha256;
    pub type RS256VerifyingKey = VerifyingKey<Sha256>;
    pub type RS256SigningKey = SigningKey<Sha256>;

    pub fn new_key(bits: usize) -> rsa::errors::Result<RsaPrivateKey> {
        let bits = std::cmp::max(bits, MIN_BITS);
        let mut rng = rand::thread_rng();
        RsaPrivateKey::new(&mut rng, bits)
    }

    pub fn oaep_sha256_encrypt(
        public_key: &RsaPublicKey,
        data: &[u8],
    ) -> rsa::errors::Result<Vec<u8>> {
        let mut rng = rand::thread_rng();
        let padding = Oaep::new::<Sha256>();
        public_key.encrypt(&mut rng, padding, data)
    }

    pub fn oaep_sha256_decrypt(
        private_key: &RsaPrivateKey,
        ciphertext: &[u8],
    ) -> rsa::errors::Result<Vec<u8>> {
        let padding = Oaep::new::<Sha256>();
        private_key.decrypt(padding, ciphertext)
    }
}

pub mod ecdsa_p256 {
    use ecdsa::hazmat::DigestPrimitive;
    use ecdsa::{Signature, SigningKey, VerifyingKey};
    use elliptic_curve::sec1::EncodedPoint;
    use elliptic_curve::{FieldBytes, PublicKey, SecretKey};
    use generic_array::GenericArray;
    use p256::NistP256;
    use sha2::digest::consts::U32;

    pub type EcdsaP256Digest = <NistP256 as DigestPrimitive>::Digest;

    pub type EcdsaP256PrivateKey = SecretKey<NistP256>;
    pub type EcdsaP256PrivateKeyFieldBytes = FieldBytes<NistP256>;

    pub type EcdsaP256PublicKey = PublicKey<NistP256>;

    pub type EcdsaP256PublicCoordinate = GenericArray<u8, U32>;
    pub type EcdsaP256PublicEncodedPoint = EncodedPoint<NistP256>;

    pub type EcdsaP256SigningKey = SigningKey<NistP256>;
    pub type EcdsaP256VerifyingKey = VerifyingKey<NistP256>;

    pub type EcdsaP256Signature = Signature<NistP256>;

    pub fn new_key() -> EcdsaP256PrivateKey {
        let mut rng = rand::thread_rng();
        EcdsaP256PrivateKey::random(&mut rng)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn sha256_basic() {
        use crate::s256::*;
        use crate::traits::*;

        let mut hasher = Sha256::new();
        hasher.update(&[0, 1, 2, 3]);
        let out: Sha256Output = hasher.finalize();

        eprintln!("{:?}", out.as_slice());
    }

    #[test]
    fn hmac_256_basic() {
        use crate::hmac_s256::*;

        let hmac_key = new_key();

        let mut hmac = HmacSha256::new(&hmac_key);
        hmac.update(&[0, 1, 2, 3]);
        let out = hmac.finalize();

        eprintln!("{:?}", out.into_bytes());
    }

    #[test]
    fn hmac_512_basic() {
        use crate::hmac_s512::*;

        let hmac_key = new_hmac_sha512_key();

        let mut hmac = HmacSha512::new(&hmac_key);
        hmac.update(&[0, 1, 2, 3]);
        let out = hmac.finalize();

        eprintln!("{:?}", out.into_bytes());
    }

    #[test]
    fn aes256gcm_basic() {
        use crate::aes256;
        use crate::aes256gcm::*;

        let aes256gcm_key = aes256::new_key();

        let cipher = Aes256Gcm::new(&aes256gcm_key);

        let nonce = new_nonce();

        // These are the "basic" encrypt/decrypt which postfixs a tag.
        let ciphertext = cipher
            .encrypt(&nonce, b"plaintext message".as_ref())
            .unwrap();
        let plaintext = cipher.decrypt(&nonce, ciphertext.as_ref()).unwrap();

        assert_eq!(&plaintext, b"plaintext message");

        // For control of the tag, the following is used.

        // Never re-use nonces
        let nonce = new_nonce();

        let mut buffer = Vec::from(b"test message, super cool");

        // Same as "None"
        let associated_data = b"";

        let tag = cipher
            .encrypt_in_place_detached(&nonce, associated_data, buffer.as_mut_slice())
            .unwrap();

        cipher
            .decrypt_in_place_detached(&nonce, associated_data, &mut buffer, &tag)
            .unwrap();

        assert_eq!(buffer, b"test message, super cool");
    }

    #[test]
    fn aes256cbc_basic() {
        use crate::aes256;
        use crate::aes256cbc::{self, *};

        let key = aes256::new_key();
        let iv = aes256cbc::new_iv();

        let enc = aes256cbc::Aes256CbcEnc::new(&key, &iv);

        let ciphertext = enc.encrypt_padded_vec_mut::<block_padding::Pkcs7>(b"plaintext message");

        let dec = aes256cbc::Aes256CbcDec::new(&key, &iv);

        let plaintext = dec
            .decrypt_padded_vec_mut::<block_padding::Pkcs7>(&ciphertext)
            .expect("Unpadding Failed");

        assert_eq!(plaintext, b"plaintext message");
    }

    #[test]
    fn aes256cbc_hmac_basic() {
        use crate::aes256;
        use crate::aes256cbc::{self, block_padding};

        let key = aes256::new_key();

        let (mac, iv, ciphertext) =
            aes256cbc::enc::<block_padding::Pkcs7>(&key, b"plaintext message").unwrap();

        let plaintext =
            aes256cbc::dec::<block_padding::Pkcs7>(&key, &mac, &iv, &ciphertext).unwrap();

        assert_eq!(plaintext, b"plaintext message");
    }

    #[test]
    fn aes256kw_basic() {
        use crate::aes256;
        use crate::aes256kw::*;

        let key_wrap_key = aes256::new_key();
        let key_wrap = Aes256Kw::new(&key_wrap_key);

        let key_to_wrap = aes256::new_key();
        let mut wrapped_key = Aes256KwWrapped::default();

        // Wrap it.
        key_wrap.wrap(&key_to_wrap, &mut wrapped_key).unwrap();
        // Reverse the process

        let mut key_unwrapped = aes256::Aes256Key::default();

        key_wrap.unwrap(&wrapped_key, &mut key_unwrapped).unwrap();

        assert_eq!(key_to_wrap, key_unwrapped);
    }

    #[test]
    fn rsa_basic() {
        use crate::rsa::*;
        use crate::traits::*;

        let pkey = new_key(MIN_BITS).unwrap();

        let pubkey = RS256PublicKey::from(&pkey);

        // OAEP

        let ciphertext = oaep_sha256_encrypt(&pubkey, b"this is a message").unwrap();

        let plaintext = oaep_sha256_decrypt(&pkey, &ciphertext).unwrap();

        assert_eq!(plaintext, b"this is a message");

        // PKCS1.5 Sig
        let signing_key = RS256SigningKey::new(pkey);
        let verifying_key = RS256VerifyingKey::new(pubkey);

        let mut rng = rand::thread_rng();

        let data = b"Fully sick data to sign mate.";

        let signature = signing_key.sign_with_rng(&mut rng, data);
        assert!(verifying_key.verify(data, &signature).is_ok());

        let signature = signing_key.sign(data);
        assert!(verifying_key.verify(data, &signature).is_ok());
    }

    #[test]
    fn ecdsa_p256_basic() {
        use crate::ecdsa_p256::*;
        use crate::traits::*;

        let priv_key = new_key();

        let pub_key = priv_key.public_key();

        let signer = EcdsaP256SigningKey::from(&priv_key);
        let verifier = EcdsaP256VerifyingKey::from(&pub_key);

        // Can either sign data directly, using the correct associated hash type.
        let data = [0, 1, 2, 3, 4, 5, 6, 7];

        let sig: EcdsaP256Signature = signer.try_sign(&data).unwrap();

        assert!(verifier.verify(&data, &sig).is_ok());

        // Or you can sign a digest directly, must match the type from C::Digest.

        let mut digest = EcdsaP256Digest::new();
        digest.update(&data);

        let sig: EcdsaP256Signature = signer.try_sign_digest(digest).unwrap();
        assert!(verifier.verify(&data, &sig).is_ok());
    }

    #[test]
    fn rustls_mtls_basic() {
        use rustls::{
            self,
            client::{ClientConfig, ClientConnection},
            pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
            server::{ServerConfig, ServerConnection},
            RootCertStore,
        };
        use std::io::Read;
        use std::io::Write;
        use std::os::unix::net::UnixStream;
        use std::sync::Arc;

        use std::sync::atomic::{AtomicU16, Ordering};

        use std::str::FromStr;
        use std::time::Duration;
        use std::time::SystemTime;
        use x509_cert::der::Encode;
        use x509_cert::name::Name;
        use x509_cert::time::Time;

        use elliptic_curve::SecretKey;

        use crate::test_ca::*;

        // ========================
        // CA SETUP

        let now = SystemTime::now();
        let not_before = Time::try_from(now).unwrap();
        let not_after = Time::try_from(now + Duration::new(3600, 0)).unwrap();

        let (root_signing_key, root_ca_cert) = build_test_ca_root(not_before, not_after);

        let mut root_ca_cert_display = String::default();

        crate::x509::display::cert_to_string_pretty(&root_ca_cert, &mut root_ca_cert_display)
            .unwrap();

        eprintln!("{}", &root_ca_cert_display);

        let subject = Name::from_str("CN=localhost").unwrap();

        let (server_key, server_csr) = build_test_csr(not_before, not_after, subject);

        let server_cert = test_ca_sign_server_csr(
            not_before,
            not_after,
            &server_csr,
            &root_signing_key,
            &root_ca_cert,
        );

        let mut server_cert_display = String::default();

        crate::x509::display::cert_to_string_pretty(&server_cert, &mut server_cert_display)
            .unwrap();

        eprintln!("{}", &server_cert_display);

        // ========================
        use p384::pkcs8::EncodePrivateKey;
        let server_private_key_pkcs8_der = SecretKey::from(server_key).to_pkcs8_der().unwrap();

        let root_ca_cert_der = root_ca_cert.to_der().unwrap();
        let server_cert_der = server_cert.to_der().unwrap();

        let mut ca_roots = RootCertStore::empty();

        ca_roots
            .add(CertificateDer::from(root_ca_cert_der.clone()))
            .unwrap();

        let server_chain = vec![
            CertificateDer::from(server_cert_der),
            CertificateDer::from(root_ca_cert_der),
        ];

        let server_private_key: PrivateKeyDer =
            PrivatePkcs8KeyDer::from(server_private_key_pkcs8_der.as_bytes().to_vec()).into();

        let provider = Arc::new(rustls_rustcrypto::provider());

        let client_tls_config: Arc<_> = ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(ca_roots)
            .with_no_client_auth()
            .into();

        let server_tls_config: Arc<_> = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(server_chain, server_private_key)
            .map(Arc::new)
            .expect("bad certificate/key");

        let server_name = ServerName::try_from("localhost").expect("invalid DNS name");

        let (mut server_unix_stream, mut client_unix_stream) = UnixStream::pair().unwrap();

        let atomic = Arc::new(AtomicU16::new(0));

        let atomic_t = atomic.clone();

        let handle = std::thread::spawn(move || {
            let mut client_connection =
                ClientConnection::new(client_tls_config, server_name).unwrap();

            let mut client = rustls::Stream::new(&mut client_connection, &mut client_unix_stream);

            client.write_all(b"hello").unwrap();

            while atomic_t.load(Ordering::Relaxed) != 1 {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }

            println!("THREAD DONE");
        });

        let mut server_connection = ServerConnection::new(server_tls_config).unwrap();

        server_connection
            .complete_io(&mut server_unix_stream)
            .unwrap();

        server_connection
            .complete_io(&mut server_unix_stream)
            .unwrap();

        let mut buf: [u8; 5] = [0; 5];
        server_connection.reader().read(&mut buf).unwrap();

        assert_eq!(&buf, b"hello");

        atomic.store(1, Ordering::Relaxed);

        // If the thread paniced, this will panic.
        handle.join().unwrap();
    }
}
