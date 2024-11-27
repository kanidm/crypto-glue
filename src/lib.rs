pub use argon2;
pub use hex;
pub use rand;
pub use zeroize;

pub mod prelude {}

#[cfg(test)]
mod test_ca;

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

    pub fn key_from_bytes(bytes: Vec<u8>) -> Option<Aes256Key> {
        Key::<aes::Aes256>::from_exact_iter(bytes.into_iter()).map(|key| key.into())
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

    use x509_cert::ext::pkix::name::GeneralName;

    use std::fmt::Write;
    use std::fmt;
    use x509_cert::ext::pkix::SubjectKeyIdentifier;
    use x509_cert::spki::SubjectPublicKeyInfoRef;
    use x509_cert::ext::pkix::KeyUsage;
    use x509_cert::ext::pkix::AuthorityKeyIdentifier;
    use x509_cert::ext::pkix::ExtendedKeyUsage;
    use x509_cert::der::Decode;
    use x509_cert::ext::pkix::BasicConstraints;
    use x509_cert::der::referenced::OwnedToRef;

    use const_oid::AssociatedOid;

    pub fn uuid_to_serial(serial_uuid: uuid::Uuid) -> SerialNumber {
        let mut serial_bytes: [u8; 17] = [0; 17];
        serial_bytes[0] = 0x01;
        let mut update_bytes = &mut serial_bytes[1..];
        update_bytes.copy_from_slice(serial_uuid.as_bytes());

        SerialNumber::new(&serial_bytes).unwrap()
    }

    
fn write_bytes_pretty(
    indent: &str,
    bytes: &[u8],
    f: &mut String,
) -> Result<(), fmt::Error> {

    let mut iter = bytes.iter().peekable();

    write!(f, "{indent}")?;

    let mut count = 0;
    while let Some(byte) = iter.next() {
        write!(f, "{:02x}", byte)?;

        count += 1;

        if count % 18 == 0 {
            write!(f, "\n{indent}")?;
        } else if iter.peek().is_some() {
            write!(f, ":")?;
        }
    }

    Ok(())
}


fn general_name_pretty(
    g_name: &GeneralName,
    f: &mut String,
) -> Result<(), fmt::Error> {
    match g_name {
        GeneralName::OtherName(othername) => {
            write!(f, "Other: TODO")
        }
        GeneralName::Rfc822Name(ia5str) => {
            write!(f, "Email: {ia5str}")
        }
        GeneralName::DnsName(ia5str) => {
            write!(f, "DNS: {ia5str}")
        }
        GeneralName::DirectoryName(name) => {
            write!(f, "DN: {name}")
        }
        GeneralName::EdiPartyName(edi_party_name) => {
            write!(f, "EdiParty: TODO")
        }
        GeneralName::UniformResourceIdentifier(ia5str) => {
            write!(f, "URI: {ia5str}")
        }
        GeneralName::IpAddress(octet_str) => {
            write!(f, "IpAddress: TODO")
        }
        GeneralName::RegisteredId(oid) => {
            write!(f, "OID: {oid}")
        }
    }
}

fn subject_public_key_pretty(
    spki: SubjectPublicKeyInfoRef<'_>,
    indent: &str,
    indent_two: &str,
    indent_three: &str,
    f: &mut String,
) -> Result<(), fmt::Error> {
    write!(f, "{indent}Subject Public Key Info:\n")?;

    write!(f, "{indent_two}Algorithm: ")?;

    let alg_oid = &spki.algorithm.oid;

    match alg_oid {
        &const_oid::db::rfc5912::ID_EC_PUBLIC_KEY => write!(f, "id-ec-public-key")?,
        oid => write!(f, "OID= {:?}", oid)?,
    }
    write!(f, "\n")?;

    if let Ok(param_oid) = spki.algorithm.parameters_oid() {
        write!(f, "{indent_two}Parameters: ")?;
        match param_oid {
            const_oid::db::rfc5912::SECP_384_R_1 => write!(f, "SEC P384 R1")?,
            const_oid::db::rfc5912::SECP_256_R_1 => write!(f, "SEC P256 R1")?,
            oid => write!(f, "OID= {:?}", oid)?,
        }
        write!(f, "\n")?;
    }

    write!(f, "{indent_two}Public Key:\n")?;
    let sk_bytes = spki.subject_public_key.as_bytes().unwrap();
    write_bytes_pretty(indent_three, sk_bytes, f)?;

    write!(f, "\n")
}


pub(crate) fn cert_to_string_pretty(
    cert: &x509_cert::certificate::Certificate,
    f: &mut String,
) -> Result<(), fmt::Error> {

    let indent = "  ";
    let indent_two = "    ";
    let indent_three = "      ";
    let indent_four = "        ";
    let indent_five = "          ";

/*
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 4099 (0x1003)
        Signature Algorithm: ecdsa-with-SHA384
        Issuer: C=AU, ST=Queensland, O=Blackhats, CN=Blackhats Intermediate CA IDM R1
        Validity
            Not Before: Apr 30 04:11:27 2024 GMT
            Not After : Apr 29 04:11:27 2028 GMT
        Subject: CN=18412815
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (384 bit)
                pub:
                    04:2e:ee:49:3e:cb:82:0a:39:f8:24:5a:a2:e4:45:
                    d4:66:99:fa:79:4e:6f:99:80:50:0d:b0:dc:ed:7c:
                    8f:ea:79:00:b3:9e:09:0c:a6:e1:a3:9e:fa:d5:80:
                    51:83:b2:9f:ef:1c:88:bf:83:08:e3:84:0b:32:6a:
                    53:17:b2:63:20:3e:61:a9:a0:53:32:86:23:82:da:
                    0a:7b:26:6d:e8:30:59:b9:7d:7e:d9:91:3f:c2:18:
                    23:1a:98:bb:1e:71:07
                ASN1 OID: secp384r1
                NIST CURVE: P-384
        X509v3 extensions:
            X509v3 Basic Constraints:
                CA:FALSE
            X509v3 Subject Key Identifier:
                CC:31:D1:DD:C8:63:DA:59:73:2B:51:3B:D4:CB:B7:9F:4D:10:81:A6
            X509v3 Authority Key Identifier:
                DF:A8:A6:C9:90:3F:86:E4:27:7E:8B:B3:4C:E0:F2:E9:A7:09:FB:5C
            X509v3 Key Usage: critical
                Digital Signature, Non Repudiation, Key Encipherment
            X509v3 Extended Key Usage:
                TLS Web Client Authentication
    Signature Algorithm: ecdsa-with-SHA384
    Signature Value:
        30:66:02:31:00:d8:04:1d:02:66:7a:58:b5:66:6c:16:4e:4a:
        0b:43:4d:f3:99:5b:c9:cb:8e:4f:1e:17:45:2f:c1:32:ba:29:
        1e:f8:12:b2:6d:1d:bb:2a:9a:13:c5:5c:f0:3f:20:26:58:02:
        31:00:dc:0e:9c:d8:e3:13:8f:48:e6:2f:c9:88:ae:6a:de:d9:
        bc:d0:9f:48:77:f9:4b:f1:74:4e:2a:34:34:52:12:16:70:50:
        c4:b2:ef:71:0f:a3:87:ee:79:21:6b:d1:a3:9f
*/

    write!(f, "Certificate:\n")?;

    // cert.tbs_certificate
    write!(f, "{indent}Data:\n")?;

    // Version
    write!(f, "{indent_two}Version: {:?}\n", cert.tbs_certificate.version)?;

    // Serial
    write!(f, "{indent_two}Serial:\n")?;
    write_bytes_pretty(indent_three, cert.tbs_certificate.serial_number.as_bytes(), f)?;
    write!(f, "\n");

    // Subject
    write!(f, "{indent_two}Subject: {}\n", cert.tbs_certificate.subject)?;

    // Issuer
    write!(f, "{indent_two}Issuer: {}\n", cert.tbs_certificate.issuer)?;

    // Issuer Unique Id
    if let Some(issuer_unique_id) = &cert.tbs_certificate.issuer_unique_id {
        write!(f, "{indent_two}Issuer Unique ID:\n")?;
        write_bytes_pretty(indent_three, issuer_unique_id.as_bytes().unwrap(), f)?;
        write!(f, "\n");
    }

    // Subject Unique Id
    if let Some(subject_unique_id) = &cert.tbs_certificate.subject_unique_id {
        write!(f, "{indent_two}Subject Unique ID:\n")?;
        write_bytes_pretty(indent_three, subject_unique_id.as_bytes().unwrap(), f)?;
        write!(f, "\n");
    }

    // Validity
    write!(f, "{indent_two}Validity\n")?;
    write!(f, "{indent_three}Not Before: {}\n", cert.tbs_certificate.validity.not_before)?;
    write!(f, "{indent_three}Not After: {}\n", cert.tbs_certificate.validity.not_after)?;

    // Signature Algorithm:
    write!(f, "{indent_two}Signature Algorithm: ")?;
    match &cert.tbs_certificate.signature.oid {
        &const_oid::db::rfc5912::ECDSA_WITH_SHA_256 => write!(f, "ecdsa-with-sha256")?,
        &const_oid::db::rfc5912::ECDSA_WITH_SHA_384 => write!(f, "ecdsa-with-sha384")?,
        &const_oid::db::rfc5912::ECDSA_WITH_SHA_512 => write!(f, "ecdsa-with-sha512")?,
        &const_oid::db::rfc5912::SHA_256_WITH_RSA_ENCRYPTION => write!(f, "sha256-with-rsa-encryption")?,
        oid => write!(f, "OID= {:?}", oid)?,
    }
    write!(f, "\n")?;

    // SubjectPublic Key Info
    subject_public_key_pretty(
        cert.tbs_certificate.subject_public_key_info.owned_to_ref(),
        indent_two,
        indent_three,
        indent_four,
        f,
    )?;

    // Display Extensions
    for extension in cert.tbs_certificate.extensions.iter().flat_map(|exts| exts.iter()) {
        match extension.extn_id {
            BasicConstraints::OID => {
                let bc = BasicConstraints::from_der(extension.extn_value.as_bytes()).expect("Invalid Basic Constraints");
                write!(f, "{indent_three}Basic Constraints:")?;
                if extension.critical {
                    write!(f, " critical")?;
                }
                write!(f, "\n")?;

                write!(f, "{indent_four}CA: {}\n", bc.ca)?;
                if let Some(path_len_constraint) = bc.path_len_constraint {
                    write!(f, "{indent_four}Path Length: {}\n", path_len_constraint)?;
                }
            }

            // Subject Key ID
            // 2.5.29.14
            SubjectKeyIdentifier::OID => {
                let ski = SubjectKeyIdentifier::from_der(extension.extn_value.as_bytes()).expect("Invalid Subject Key ID");

                write!(f, "{indent_three}Subject Key Identifier:")?;
                if extension.critical {
                    write!(f, " critical")?;
                }
                write!(f, "\n")?;

                write_bytes_pretty(indent_four, ski.as_ref().as_bytes(), f)?;

                write!(f, "\n")?;
            }

            // Key Usage
            // 2.5.29.15
            KeyUsage::OID => {
                let ku = KeyUsage::from_der(extension.extn_value.as_bytes()).expect("Invalid Key Usage");

                write!(f, "{indent_three}Key Usage:")?;
                if extension.critical {
                    write!(f, " critical")?;
                }
                write!(f, "\n")?;

                if ku.digital_signature() {
                    write!(f, "{indent_four}Digital Signature\n")?;
                }

                if ku.non_repudiation() {
                    write!(f, "{indent_four}Non Repudiation\n")?;
                }

                if ku.key_encipherment() {
                    write!(f, "{indent_four}Key Encipherment\n")?;
                }

                if ku.data_encipherment() {
                    write!(f, "{indent_four}Data Encipherment\n")?;
                }

                if ku.key_agreement() {
                    write!(f, "{indent_four}Key Agreement\n")?;
                }

                if ku.key_cert_sign() {
                    write!(f, "{indent_four}Key Cert Sign\n")?;
                }

                if ku.crl_sign() {
                    write!(f, "{indent_four}CRL Sign\n")?;
                }

                if ku.encipher_only() {
                    write!(f, "{indent_four}Encipher Only\n")?;
                }

                if ku.decipher_only() {
                    write!(f, "{indent_four}Decipher Only\n")?;
                }

            }

            // Authority Key ID
            // 2.5.29.35

            AuthorityKeyIdentifier::OID => {
                let aki = AuthorityKeyIdentifier::from_der(extension.extn_value.as_bytes()).expect("Invalid Authority Key ID");

                write!(f, "{indent_three}Authority Key Identifier:")?;
                if extension.critical {
                    write!(f, " critical")?;
                }
                write!(f, "\n")?;

                if let Some(key_id) = &aki.key_identifier {
                    write_bytes_pretty(indent_four, key_id.as_ref(), f)?;
                    write!(f, "\n")?;
                }

                if let Some(aki_cert_issuer) = &aki.authority_cert_issuer {
                    for g_name in aki_cert_issuer.iter() {
                        write!(f, "{indent_four}")?;
                        general_name_pretty(g_name, f)?;
                        write!(f, "\n")?;
                    }
                }

                if let Some(aki_cert_serial) = &aki.authority_cert_serial_number {
                    write_bytes_pretty(indent_four, aki_cert_serial.as_bytes(), f)?;
                    write!(f, "\n");
                }


            }

            // Extended Key Usage
            // 2.5.29.37
            ExtendedKeyUsage::OID => {
                let eku = ExtendedKeyUsage::from_der(extension.extn_value.as_bytes()).expect("Invalid Extended Key Usage");

                write!(f, "{indent_three}Authority Key Identifier:")?;
                if extension.critical {
                    write!(f, " critical")?;
                }
                write!(f, "\n")?;

                for oid in eku.as_ref().iter() {
                    write!(f, "{indent_four}")?;
                    match oid {
                        &const_oid::db::rfc5280::ID_KP_SERVER_AUTH => write!(f, "Server Authentication")?,
                        &const_oid::db::rfc5280::ID_KP_CLIENT_AUTH => write!(f, "Client Authentication")?,
                        &const_oid::db::rfc5280::ID_KP_CODE_SIGNING => write!(f, "Code Signing")?,
                        oid => write!(f, "OID= {:?}", oid)?,
                    }
                    write!(f, "\n")?;
                }
            }

            oid => {
                // Probably in RFC5280
                write!(f, "{indent_three}Unknown Extension: OID= {:?}\n", oid)?
            }
        }
    }

    // == Signature Algorthim
    write!(f, "{indent}Signature Algorithm: ")?;
    match &cert.signature_algorithm.oid {
        &const_oid::db::rfc5912::ECDSA_WITH_SHA_256 => write!(f, "ecdsa-with-sha256")?,
        &const_oid::db::rfc5912::ECDSA_WITH_SHA_384 => write!(f, "ecdsa-with-sha384")?,
        &const_oid::db::rfc5912::ECDSA_WITH_SHA_512 => write!(f, "ecdsa-with-sha512")?,
        &const_oid::db::rfc5912::SHA_256_WITH_RSA_ENCRYPTION => write!(f, "sha256-with-rsa-encryption")?,
        oid => write!(f, "OID= {:?}", oid)?,
    }
    write!(f, "\n")?;

    // == Signature
    // let cert_sig = hex::encode(cert.signature.as_bytes()?);
    // write!(f, "{indent}Signature: {}\n", cert_sig)?;

    write!(f, "{indent}Signature:\n")?;
    let c_bytes = cert.signature.as_bytes().unwrap();
    write_bytes_pretty(indent_two, c_bytes, f)?;
    write!(f, "\n")?;

    // == Done
    Ok(())
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
        use crate::ecdsa_p256::*;
        use rustls::{
            self,
            client::{ClientConfig, ClientConnection},
            pki_types::{CertificateDer, PrivateKeyDer, PrivateSec1KeyDer, PrivatePkcs8KeyDer, ServerName},
            server::{ServerConfig, ServerConnection},
            RootCertStore,
        };
        use rustls::pki_types::pem::PemObject;

        use std::os::unix::net::UnixStream;
        use std::sync::Arc;

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

        crate::x509::cert_to_string_pretty(&root_ca_cert, &mut root_ca_cert_display).unwrap();

        eprintln!("{}", &root_ca_cert_display);

        let subject = Name::from_str("CN=localhost").unwrap();

        let (server_key, server_csr) = build_test_csr(not_before, not_after, subject);

        let (server_cert) = test_ca_sign_server_csr(
            not_before,
            not_after,
            &server_csr,
            &root_signing_key,
            &root_ca_cert,
        );

        let mut server_cert_display = String::default();

        crate::x509::cert_to_string_pretty(&server_cert, &mut server_cert_display).unwrap();

        eprintln!("{}", &server_cert_display);

        // ========================
        use p384::pkcs8::EncodePrivateKey;
        let server_private_key_pkcs8_der = SecretKey::from(server_key).to_pkcs8_der().unwrap();

        let root_ca_cert_der = root_ca_cert.to_der().unwrap();
        let server_cert_der = server_cert.to_der().unwrap();

        let mut ca_roots = RootCertStore::empty();

        ca_roots.add(CertificateDer::from(root_ca_cert_der.clone()));

        let server_chain = vec![
            CertificateDer::from(root_ca_cert_der),
            CertificateDer::from(server_cert_der),
        ];

        let server_private_key: PrivateKeyDer =
            PrivatePkcs8KeyDer::from(server_private_key_pkcs8_der.as_bytes().to_vec())
                // .unwrap()
                .into();

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

        let mut client_connection = ClientConnection::new(client_tls_config, server_name).unwrap();

        let mut server_connection = ServerConnection::new(server_tls_config).unwrap();

        let (mut server_unix_stream, mut client_unix_stream) = UnixStream::pair().unwrap();

        let mut client = rustls::Stream::new(&mut client_connection, &mut client_unix_stream);

        let mut server = rustls::Stream::new(&mut server_connection, &mut server_unix_stream);

        // One of these needs to go to a thread somewhere.
    }
}
