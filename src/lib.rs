pub use argon2;
pub use hex;
pub use rand;
pub use zeroize;

pub mod prelude {}

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

    pub fn new_hmac_sha256_key() -> HmacSha256Key {
        use crypto_common::KeyInit;

        let mut rng = rand::thread_rng();
        HmacSha256::generate_key(&mut rng).into()
    }

    pub fn hmac_sha256_oneshot(key: &HmacSha256Key, data: &[u8]) -> HmacSha256Output {
        let mut hmac = HmacSha256::new(&key);
        hmac.update(data);
        hmac.finalize()
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

    pub fn hmac_sha512_oneshot(key: &HmacSha512Key, data: &[u8]) -> HmacSha512Output {
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

    pub fn key_from_bytes(bytes: Vec<u8> ) -> Option<Aes256Key> {
        Key::<aes::Aes256>::from_exact_iter(bytes.into_iter())
            .map(|key| key.into())
    }

    pub fn new_key() -> Aes256Key {
        let mut rng = rand::thread_rng();
        aes::Aes256::generate_key(&mut rng).into()
    }
}

pub mod aes256gcm {
    use aes::cipher::consts::{U12, U16};
    use aes_gcm::aead::AeadCore;
    use generic_array::GenericArray;

    pub use aes_gcm::aead::{Aead, AeadInPlace, Payload};
    pub use crypto_common::KeyInit;

    pub use crate::aes256::Aes256Key;

    pub type Aes256Gcm = aes_gcm::Aes256Gcm;

    pub type Aes256GcmNonce = GenericArray<u8, U12>;

    pub type Aes256GcmTag = GenericArray<u8, U16>;

    pub fn new_nonce() -> Aes256GcmNonce {
        let mut rng = rand::thread_rng();

        Aes256Gcm::generate_nonce(&mut rng)
    }
}

pub mod aes256cbc {
    use crate::hmac_s256::HmacSha256;
    use aes::cipher::consts::U16;
    use generic_array::GenericArray;
    use crate::hmac_s256::HmacSha256Output;

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
    pub use rand;
    pub use rsa::pkcs1v15::{SigningKey, VerifyingKey};
    pub use rsa::signature::{Keypair, RandomizedSigner, Verifier};
    pub use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
    pub use sha2::Sha256;

    pub const MIN_BITS: usize = 2048;

    pub fn new_rsa_key(bits: usize) -> rsa::errors::Result<RsaPrivateKey> {
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
    use elliptic_curve::{PublicKey, SecretKey};
    use p256::NistP256;

    pub use ecdsa::signature::{DigestSigner, Signer, Verifier};
    pub use ecdsa::{Signature, SigningKey, VerifyingKey};
    pub use sha2::Digest;

    pub type EcdsaP256Digest = <NistP256 as DigestPrimitive>::Digest;

    pub type EcdsaP256PrivateKey = SecretKey<NistP256>;
    pub type EcdsaP256PublicKey = PublicKey<NistP256>;

    pub type EcdsaP256SigningKey = SigningKey<NistP256>;
    pub type EcdsaP256VerifyingKey = VerifyingKey<NistP256>;

    pub type EcdsaP256Signature = Signature<NistP256>;

    pub fn new_p256_key() -> EcdsaP256PrivateKey {
        let mut rng = rand::thread_rng();
        EcdsaP256PrivateKey::random(&mut rng)
    }
}

pub mod x509 {
    use x509_cert::serial_number::SerialNumber;

    
    pub fn uuid_to_serial(serial_uuid: uuid::Uuid) -> SerialNumber {
        let mut serial_bytes: [u8; 17] = [0; 17];
        serial_bytes[0] = 0x01;
        let mut update_bytes = &mut serial_bytes[1..];
        update_bytes.copy_from_slice(serial_uuid.as_bytes());

        SerialNumber::new(&serial_bytes).unwrap()
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn hmac_256_basic() {
        use crate::hmac_s256::*;

        let hmac_key = new_hmac_sha256_key();

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

        let pkey = new_rsa_key(MIN_BITS).unwrap();

        let pubkey = RsaPublicKey::from(&pkey);

        // OAEP

        let ciphertext = oaep_sha256_encrypt(&pubkey, b"this is a message").unwrap();

        let plaintext = oaep_sha256_decrypt(&pkey, &ciphertext).unwrap();

        assert_eq!(plaintext, b"this is a message");

        // PKCS1.5 Sig
        let signing_key = SigningKey::<Sha256>::new(pkey);
        let verifying_key = signing_key.verifying_key();

        let mut rng = rand::thread_rng();

        let data = b"Fully sick data to sign mate.";
        let signature = signing_key.sign_with_rng(&mut rng, data);

        assert!(verifying_key.verify(data, &signature).is_ok());
    }

    #[test]
    fn ecdsa_p256_basic() {
        use crate::ecdsa_p256::*;

        let priv_key = new_p256_key();

        let pub_key = priv_key.public_key();

        let signer = SigningKey::from(&priv_key);
        let verifier = VerifyingKey::from(&pub_key);

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
        use std::os::unix::net::UnixStream;
        use rustls::{
            self,
            server::{
            ServerConfig, ServerConnection,
        }, client::{
            ClientConfig, ClientConnection
        }, RootCertStore, pki_types::{
            PrivateKeyDer, ServerName, PrivateSec1KeyDer
        }};
        use std::sync::Arc;
        use crate::ecdsa_p256::*;


        let server_private_key = new_p256_key();







        let server_private_key_der = server_private_key.to_sec1_der()
            .unwrap();

        let server_chain = Vec::new();
        let server_private_key: PrivateKeyDer =
            PrivateSec1KeyDer::from(server_private_key_der.as_slice().to_owned())
                .into();

        let mut ca_roots = RootCertStore::empty();


        let provider = Arc::new(rustls_rustcrypto::provider());

        let client_tls_config: Arc<_> = ClientConfig::builder_with_provider(
            provider.clone()
        )
            .with_safe_default_protocol_versions().unwrap()
            .with_root_certificates(ca_roots)
            .with_no_client_auth().into();


        let server_tls_config: Arc<_> = ServerConfig::builder_with_provider(
            provider
        )
            .with_safe_default_protocol_versions().unwrap()
            .with_no_client_auth()
            .with_single_cert(server_chain, server_private_key)
            .map(Arc::new)
            .expect("bad certificate/key");

        let server_name = ServerName::try_from("localhost").expect("invalid DNS name");

        let mut client_connection = ClientConnection::new(client_tls_config, server_name)
            .unwrap();

        let mut server_connection = ServerConnection::new(server_tls_config)
            .unwrap();

        let (mut server_unix_stream, mut client_unix_stream) = UnixStream::pair().unwrap();

        let mut client = rustls::Stream::new(&mut client_connection, &mut client_unix_stream);

        let mut server = rustls::Stream::new(&mut server_connection, &mut server_unix_stream);

        // One of these needs to go to a thread somewhere.
    }



    use std::time::{Duration, SystemTime};

    use x509_cert::builder::{Builder, CertificateBuilder, Profile, RequestBuilder};
    use x509_cert::der::Encode;
    use x509_cert::name::Name;
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::spki::SubjectPublicKeyInfoOwned;
    use x509_cert::time::{Time, Validity};

    use x509_cert::ext::pkix::{
        constraints::name::GeneralSubtree,
        constraints::BasicConstraints,
        crl::dp::DistributionPoint,
        crl::CrlDistributionPoints,
        name::{DistributionPointName, GeneralName},
        AuthorityKeyIdentifier, ExtendedKeyUsage, KeyUsage, KeyUsages, NameConstraints,
        SubjectAltName, SubjectKeyIdentifier,
    };

    use x509_cert::spki::DecodePublicKey;

    use std::str::FromStr;

    use p384::ecdsa::{signature::Signer, DerSignature, Signature, SigningKey};
    use p384::ecdsa::{signature::Verifier, VerifyingKey};

    use uuid::Uuid;
    use crate::x509::uuid_to_serial;

    // use base64::prelude::*;

    #[test]
    fn test_ca_build_process() {
        let mut rng = rand::thread_rng();

        let root_serial_uuid = Uuid::new_v4();
        let serial_number = uuid_to_serial(root_serial_uuid);

        let now = SystemTime::now();
        let not_before = Time::try_from(now).unwrap();
        let not_after = Time::try_from(now + Duration::new(3600, 0)).unwrap();

        let validity = Validity {
            not_before,
            not_after,
        };

        let profile = Profile::Root;
        let root_subject = Name::from_str("CN=Oh no he is writing a CA,O=Pls Help,C=AU").unwrap();

        let mut signing_key = SigningKey::random(&mut rng);
        let verifying_key = VerifyingKey::from(&signing_key); // Serialize with `::to_encoded_point()`
        let pub_key = SubjectPublicKeyInfoOwned::from_key(verifying_key).expect("get rsa pub key");

        let mut builder = CertificateBuilder::new(
            profile,
            serial_number,
            validity.clone(),
            root_subject.clone(),
            pub_key.clone(),
            &signing_key,
        )
        .expect("Create certificate");

        let dist_points = vec![DistributionPoint {
            distribution_point: Some(DistributionPointName::FullName(vec![
                GeneralName::UniformResourceIdentifier(
                    "https://example.com/crl".to_string().try_into().unwrap(),
                ),
            ])),
            reasons: None,
            crl_issuer: None,
        }];

        let crl_extension = CrlDistributionPoints(dist_points);

        builder
            .add_extension(&crl_extension)
            .expect("Unable to add extension");

        let cert = builder.build_with_rng::<DerSignature>(&mut rng).unwrap();

        let cert_der = cert.to_der().unwrap();
        println!("{:?}", cert);

        let cert_bytes = cert.tbs_certificate.to_der().unwrap();

        let byte_sig: &[u8] = cert.signature.as_bytes().unwrap().into();
        let cert_sig = DerSignature::try_from(byte_sig).unwrap();
        assert!(verifying_key.verify(&cert_bytes, &cert_sig).is_ok());

        // For a root cert we must validate
        //
        //   Basic Constraints: critical
        //     CA: True
        let (critical, basic_constraints) = cert
            .tbs_certificate
            .get::<BasicConstraints>()
            .expect("failed to get extensions")
            .expect("basic constraints not present");

        assert!(critical);
        eprintln!("{:?}", basic_constraints);

        assert!(basic_constraints.ca);
        assert!(basic_constraints.path_len_constraint.is_none());

        //   Key Usage: critical
        //     Certificate Sign
        //     CRL Sign

        let (critical, key_usage) = cert
            .tbs_certificate
            .get::<KeyUsage>()
            .expect("failed to get extensions")
            .expect("key usage not present");

        assert!(critical);

        eprintln!("{:?}", key_usage);
        let expected_key_usages = KeyUsages::KeyCertSign | KeyUsages::CRLSign;
        assert_eq!(key_usage, expected_key_usages.into());

        //   Subject Key ID
        //     (Should be sha1 of the public key?)
        let (_, ca_subject_key_id) = cert
            .tbs_certificate
            .get::<SubjectKeyIdentifier>()
            .expect("failed to get extensions")
            .expect("key usage not present");

        eprintln!("{:?}", ca_subject_key_id);

        //   Validity
        assert_eq!(
            cert.tbs_certificate.validity.not_before.to_unix_duration(),
            validity.not_before.to_unix_duration()
        );
        assert_eq!(
            cert.tbs_certificate.validity.not_after.to_unix_duration(),
            validity.not_after.to_unix_duration()
        );

        //   Issuer == Subject

        assert_eq!(cert.tbs_certificate.issuer, cert.tbs_certificate.subject,);

        //   Serial Number - We have to drop the first byte.
        println!("{:?}", &cert.tbs_certificate.serial_number.as_bytes()[1..]);
        println!("{:?}", root_serial_uuid.as_bytes());
        let verify_serial =
            Uuid::from_slice(&cert.tbs_certificate.serial_number.as_bytes()[1..]).unwrap();

        assert_eq!(root_serial_uuid, verify_serial);

        // CRL
        //   It's there. Trust me.

        // =========================================================================================

        let int_serial_uuid = Uuid::new_v4();

        let mut serial_bytes: [u8; 17] = [0; 17];
        serial_bytes[0] = 0x01;
        let mut update_bytes = &mut serial_bytes[1..];
        update_bytes.copy_from_slice(int_serial_uuid.as_bytes());
        drop(update_bytes);

        println!("{:?}", serial_bytes);
        let serial_number = SerialNumber::new(&serial_bytes).unwrap();

        let validity = Validity {
            not_before,
            not_after,
        };

        let profile = Profile::SubCA {
            issuer: root_subject.clone(),
            path_len_constraint: Some(0),
        };
        let int_subject = Name::from_str("CN=Oh no its an intermediate,C=AU").unwrap();

        let mut int_signing_key = SigningKey::random(&mut rng);
        let int_verifying_key = VerifyingKey::from(&int_signing_key); // Serialize with `::to_encoded_point()`
        let int_pub_key =
            SubjectPublicKeyInfoOwned::from_key(int_verifying_key).expect("get rsa pub key");

        let mut builder = CertificateBuilder::new(
            profile,
            serial_number,
            validity.clone(),
            int_subject.clone(),
            int_pub_key.clone(),
            &signing_key,
        )
        .expect("Create certificate");

        let dist_points = vec![DistributionPoint {
            distribution_point: Some(DistributionPointName::FullName(vec![
                GeneralName::UniformResourceIdentifier(
                    "https://example.com/int/crl"
                        .to_string()
                        .try_into()
                        .unwrap(),
                ),
            ])),
            reasons: None,
            crl_issuer: None,
        }];

        let crl_extension = CrlDistributionPoints(dist_points);

        builder
            .add_extension(&crl_extension)
            .expect("Unable to add extension");

        let name_constraint_extension = NameConstraints {
            permitted_subtrees: Some(vec![GeneralSubtree {
                base: GeneralName::DnsName("example.com".to_string().try_into().unwrap()),
                minimum: 0,
                maximum: None,
            }]),
            excluded_subtrees: None,
        };

        builder
            .add_extension(&name_constraint_extension)
            .expect("Unable to add extension");

        let int_cert = builder.build_with_rng::<DerSignature>(&mut rng).unwrap();

        let cert_der = int_cert.to_der().unwrap();
        println!("{:?}", int_cert);

        let cert_bytes = int_cert.tbs_certificate.to_der().unwrap();

        let byte_sig: &[u8] = int_cert.signature.as_bytes().unwrap().into();
        let cert_sig = DerSignature::try_from(byte_sig).unwrap();
        assert!(verifying_key.verify(&cert_bytes, &cert_sig).is_ok());

        // Intermediate:
        //   Basic Constraints: critical
        //     CA:TRUE
        //     pathlen:0  // indicates no subordinate CA's

        let (critical, basic_constraints) = int_cert
            .tbs_certificate
            .get::<BasicConstraints>()
            .expect("failed to get extensions")
            .expect("basic constraints not present");

        assert!(critical);

        eprintln!("{:?}", basic_constraints);

        assert!(basic_constraints.ca);
        assert_eq!(basic_constraints.path_len_constraint, Some(0));

        //   Key Usage: critical
        //     Digital Signature
        //     Certificate Sign
        //     CRL Sign

        let (critical, key_usage) = int_cert
            .tbs_certificate
            .get::<KeyUsage>()
            .expect("failed to get extensions")
            .expect("key usage not present");

        assert!(critical);

        eprintln!("{:?}", key_usage);
        let expected_key_usages = KeyUsages::KeyCertSign | KeyUsages::CRLSign;
        assert_eq!(key_usage, expected_key_usages.into());

        //   "Name Constraints": https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.10
        //      Only needed for "servers".

        let (critical, name_constraints) = int_cert
            .tbs_certificate
            .get::<NameConstraints>()
            .expect("failed to get extensions")
            .expect("key usage not present");

        assert!(critical);
        // Otherwise, it's there, trust me bro.

        //   Authority Key ID
        //     (Should be sha1 of the signer public key)
        let (_, authority_key_id) = int_cert
            .tbs_certificate
            .get::<AuthorityKeyIdentifier>()
            .expect("failed to get extensions")
            .expect("key usage not present");

        eprintln!("{:?}", authority_key_id);

        assert_eq!(
            authority_key_id.key_identifier.as_ref().unwrap(),
            ca_subject_key_id.as_ref()
        );

        //   Subject Key ID
        let (_, int_subject_key_id) = int_cert
            .tbs_certificate
            .get::<SubjectKeyIdentifier>()
            .expect("failed to get extensions")
            .expect("key usage not present");

        eprintln!("{:?}", int_subject_key_id);

        //   Validity
        assert_eq!(
            int_cert
                .tbs_certificate
                .validity
                .not_before
                .to_unix_duration(),
            validity.not_before.to_unix_duration()
        );
        assert_eq!(
            int_cert
                .tbs_certificate
                .validity
                .not_after
                .to_unix_duration(),
            validity.not_after.to_unix_duration()
        );

        //   Issuer == Subject of Authority Key
        assert_eq!(
            int_cert.tbs_certificate.issuer,
            cert.tbs_certificate.subject,
        );

        assert_eq!(int_cert.tbs_certificate.subject, int_subject);

        //
        //   Serial Number
        println!(
            "{:?}",
            &int_cert.tbs_certificate.serial_number.as_bytes()[1..]
        );
        println!("{:?}", int_serial_uuid.as_bytes());
        let verify_serial =
            Uuid::from_slice(&int_cert.tbs_certificate.serial_number.as_bytes()[1..]).unwrap();

        assert_eq!(int_serial_uuid, verify_serial);

        //   CRL
        //   It's there. Trust me.

        // =========================================================================================

        // Now make a CSR, which we will verify *and* then sign.

        let mut client_signing_key = SigningKey::random(&mut rng);
        let client_verifying_key = VerifyingKey::from(&client_signing_key); // Serialize with `::to_encoded_point()`
                                                                            // let int_pub_key =
                                                                            // SubjectPublicKeyInfoOwned::from_key(int_verifying_key).expect("get rsa pub key");

        let subject = Name::from_str("CN=multi pass").unwrap();

        let mut builder = RequestBuilder::new(subject.clone(), &client_signing_key)
            .expect("Create certificate request");

        let client_cert_req = builder.build_with_rng::<DerSignature>(&mut rng).unwrap();

        let client_cert_req_der = client_cert_req.to_der().unwrap();
        println!("{:?}", client_cert_req_der);

        // First, extract the public key from the cert and use it to self-verify

        // Need to check the algorithm ID in future.
        let spki = &client_cert_req.info.public_key;
        let extracted_public_key = VerifyingKey::from_public_key_der(
            // spki.subject_public_key.as_bytes().unwrap()
            spki.to_der().unwrap().as_slice(),
        )
        .expect("Unable to parse key bytes");
        assert_eq!(extracted_public_key, client_verifying_key);

        let req_bytes = client_cert_req.info.to_der().unwrap();

        let byte_sig: &[u8] = client_cert_req.signature.as_bytes().unwrap().into();
        let client_cert_req_sig = DerSignature::try_from(byte_sig).unwrap();
        assert!(extracted_public_key
            .verify(&req_bytes, &client_cert_req_sig)
            .is_ok());
        assert!(client_verifying_key
            .verify(&req_bytes, &client_cert_req_sig)
            .is_ok());

        // The process of issuance at this point really is up to "what do we want to copy from the
        // csr and what don't we?".

        // ------------------------

        let client_serial_uuid = Uuid::new_v4();

        let mut serial_bytes: [u8; 17] = [0; 17];
        serial_bytes[0] = 0x01;
        let mut update_bytes = &mut serial_bytes[1..];
        update_bytes.copy_from_slice(client_serial_uuid.as_bytes());
        drop(update_bytes);

        println!("{:?}", serial_bytes);
        let serial_number = SerialNumber::new(&serial_bytes).unwrap();

        let validity = Validity {
            not_before,
            not_after,
        };

        let profile = Profile::Leaf {
            issuer: int_subject.clone(),
            enable_key_agreement: false,
            enable_key_encipherment: true,
            include_subject_key_identifier: true,
        };

        let client_cert_subject = client_cert_req.info.subject.clone();

        let mut builder = CertificateBuilder::new(
            profile,
            serial_number,
            validity.clone(),
            client_cert_subject.clone(),
            spki.clone(),
            &int_signing_key,
        )
        .expect("Create certificate");

        let eku_extension = ExtendedKeyUsage(vec![const_oid::db::rfc5280::ID_KP_CLIENT_AUTH]);

        builder
            .add_extension(&eku_extension)
            .expect("Unable to add extension");

        let alt_name = Name::from_str("ENTRYUUID=cb98d3d3-efcc-4675-ad40-435f6280d41b").unwrap();

        let san = SubjectAltName(vec![GeneralName::DirectoryName(alt_name)]);

        builder
            .add_extension(&san)
            .expect("Unable to add extension");

        let client_cert = builder.build_with_rng::<DerSignature>(&mut rng).unwrap();

        let client_cert_der = client_cert.to_der().unwrap();
        println!("{:?}", client_cert);

        // Client Leaf Cert
        //   Basic Constraints: critical
        //     CA:FALSE

        let (critical, basic_constraints) = client_cert
            .tbs_certificate
            .get::<BasicConstraints>()
            .expect("failed to get extensions")
            .expect("basic constraints not present");

        assert!(critical);
        eprintln!("{:?}", basic_constraints);

        assert!(!basic_constraints.ca);

        //   Key Usage: critical
        //     Digital Signature
        //     Non Repudiation
        //     Key Encipherment

        let (critical, key_usage) = client_cert
            .tbs_certificate
            .get::<KeyUsage>()
            .expect("failed to get extensions")
            .expect("key usage not present");

        assert!(critical);

        eprintln!("{:?}", key_usage);
        let expected_key_usages =
            KeyUsages::DigitalSignature | KeyUsages::NonRepudiation | KeyUsages::KeyEncipherment;
        assert_eq!(key_usage, expected_key_usages.into());

        //   Extended Key Usage
        //     TLS Web Client Authentication

        let (_, key_usage) = client_cert
            .tbs_certificate
            .get::<ExtendedKeyUsage>()
            .expect("failed to get extensions")
            .expect("extended key usage not present");

        assert_eq!(key_usage.0, vec![const_oid::db::rfc5280::ID_KP_CLIENT_AUTH]);

        //   Authority Key ID
        //     (Should be sha256 of the signer public key)

        let (_, authority_key_id) = client_cert
            .tbs_certificate
            .get::<AuthorityKeyIdentifier>()
            .expect("failed to get extensions")
            .expect("key usage not present");

        eprintln!("{:?}", authority_key_id);

        assert_eq!(
            authority_key_id.key_identifier.as_ref().unwrap(),
            int_subject_key_id.as_ref()
        );

        //   Subject Key ID
        let (_, client_subject_key_id) = client_cert
            .tbs_certificate
            .get::<SubjectKeyIdentifier>()
            .expect("failed to get extensions")
            .expect("key usage not present");

        eprintln!("{:?}", client_subject_key_id);

        //   Validity
        assert_eq!(
            client_cert
                .tbs_certificate
                .validity
                .not_before
                .to_unix_duration(),
            validity.not_before.to_unix_duration()
        );
        assert_eq!(
            client_cert
                .tbs_certificate
                .validity
                .not_after
                .to_unix_duration(),
            validity.not_after.to_unix_duration()
        );

        //   Issuer == Subject of Authority Key
        assert_eq!(
            client_cert.tbs_certificate.issuer,
            int_cert.tbs_certificate.subject
        );

        //
        //  Must have
        //   Subject Alternative Name

        //   Serial Number
        println!(
            "{:?}",
            &client_cert.tbs_certificate.serial_number.as_bytes()[1..]
        );
        println!("{:?}", client_serial_uuid.as_bytes());
        let verify_serial =
            Uuid::from_slice(&client_cert.tbs_certificate.serial_number.as_bytes()[1..]).unwrap();

        assert_eq!(client_serial_uuid, verify_serial);
        //   Subject
        assert_eq!(subject, client_cert.tbs_certificate.subject);

        // =========================================================================================

        // Server Leaf Cert
        //   Basic Constraints: critical
        //     CA:FALSE
        //   Key Usage: critical
        //     Digital Signature,
        //     Non Repudiation,
        //     Key Encipherment,
        //     Key Agreement
        //   Extended Key Usage
        //     TLS Web Server Authentication
        //   Authority Key ID
        //     (Should be sha256 of the signer public key)
        //   Subject Key ID
        //   Validity
        //   Issuer == Subject of Authority Key
        //
        //  Must have
        //   Subject Alternative Name
        //     DNS: <hostname>
        //   Serial Number
        //   Subject
    }
}

