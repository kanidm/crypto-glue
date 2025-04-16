use crate::x509::{BasicConstraints, Certificate, KeyUsage};
use crate::{
    ecdsa_p256::{EcdsaP256DerSignature, EcdsaP256PublicKey, EcdsaP256VerifyingKey},
    ecdsa_p384::{EcdsaP384DerSignature, EcdsaP384PublicKey, EcdsaP384VerifyingKey},
    rsa::{RS256PublicKey, RS256Signature, RS256VerifyingKey},
    traits::Verifier,
};
use const_oid::db as oiddb;
use der::referenced::OwnedToRef;
use der::Encode;
use std::time::{Duration, SystemTime};
use tracing::error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X509VerificationError {
    InvalidSystemTime,
    BasicConstraintsNotPresent,
    LeafMustNotBeCA,
    KeyUsageNotValid,
    ExtensionFailure,
    NotBefore,
    NotAfter,
    NoMatchingIssuer,
    InvalidIssuer,
    ExcessivePathLength,
    CaNotMarkedAsSuch,
    PathLengthExceeded,
    SignatureAlgorithmMismatch,
    SignatureAlgorithmNotImplemented,
    DerSignatureInvalid,
    VerifyingKeyFromSpki,
    SignatureVerificationFailed,
    CertificateSerialisation,
    KeyUsageNotPresent,
}

pub struct X509Store {
    store: Vec<Certificate>,
}

impl X509Store {
    pub fn new(ca_roots: &[&Certificate]) -> Self {
        Self {
            store: ca_roots.iter().map(|c| (*c).clone()).collect(),
        }
    }

    pub fn verify(
        &self,
        leaf: &Certificate,
        intermediates: &[&Certificate],
        current_time: SystemTime,
    ) -> Result<(), X509VerificationError> {
        // To verify this, we need to get the "rightmost" certificate that we then
        // check is valid wrt to our store.
        //
        // Our caller has passed in:
        //
        // [ leaf, inter, inter, ... ]
        //
        // where the signing flows right to left
        //
        // [ leaf <- inter <- inter, ... ]
        //
        // So the initial stage is to validate the intermediate chain, and determine
        // the intermediate closest to the root.

        let current_time_unix = current_time
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| X509VerificationError::InvalidSystemTime)?;

        let mut certificate_to_validate = leaf;
        self.validate_leaf(certificate_to_validate, current_time_unix)?;

        // PATH LENGTH
        let mut path_length = 0;

        for intermediate in intermediates {
            // validate that intermediate signed the current certificate we
            // are scrutinising.

            self.validate_pair(
                certificate_to_validate,
                intermediate,
                current_time_unix,
                path_length,
            )?;

            // If it was valid, we now need to check the intermediate next.
            certificate_to_validate = intermediate;

            // The path length now increments by one as we added a CA to the path.
            path_length = path_length
                .checked_add(1)
                .ok_or(X509VerificationError::ExcessivePathLength)?;
        }

        // Now, the certificate_to_validate is positioned. We have either validated
        // the chain of intermediates to the leaf, or the leaf was the only certificate
        // present.

        // At this point, we now can check that our ca_store actually contains
        // something that validates this certificate.

        let authority_cert = self.locate_authority_certificate(certificate_to_validate)?;

        self.validate_pair(
            certificate_to_validate,
            authority_cert,
            current_time_unix,
            path_length,
        )?;

        // At this point we have established the chain back to the CA is valid along
        // the path of intermediates.

        // That's it!
        Ok(())
    }

    fn validate_leaf(
        &self,
        certificate_to_validate: &Certificate,
        current_time: Duration,
    ) -> Result<(), X509VerificationError> {
        // Client Leaf Cert
        //   Basic Constraints: critical
        //     CA:FALSE
        let (_critical, basic_constraints) = certificate_to_validate
            .tbs_certificate
            .get::<BasicConstraints>()
            .map_err(|_err| X509VerificationError::ExtensionFailure)?
            .ok_or(X509VerificationError::BasicConstraintsNotPresent)?;

        if basic_constraints.ca {
            return Err(X509VerificationError::LeafMustNotBeCA);
        }

        let maybe_keyusage = certificate_to_validate
            .tbs_certificate
            .get::<KeyUsage>()
            .map_err(|_err| X509VerificationError::ExtensionFailure)?;

        if let Some((_critical, key_usage)) = maybe_keyusage {
            //   Key Usage: critical
            //     Digital Signature
            if !key_usage.digital_signature() {
                return Err(X509VerificationError::KeyUsageNotValid);
            }
        }

        // Valid time range.
        let not_before = certificate_to_validate
            .tbs_certificate
            .validity
            .not_before
            .to_unix_duration();

        if not_before > current_time {
            return Err(X509VerificationError::NotBefore);
        }

        let not_after = certificate_to_validate
            .tbs_certificate
            .validity
            .not_after
            .to_unix_duration();

        if current_time > not_after {
            return Err(X509VerificationError::NotAfter);
        }

        Ok(())
    }

    fn validate_pair(
        &self,
        certificate_to_validate: &Certificate,
        authority: &Certificate,
        current_time: Duration,
        path_length: u8,
    ) -> Result<(), X509VerificationError> {
        if authority.tbs_certificate.subject != certificate_to_validate.tbs_certificate.issuer {
            return Err(X509VerificationError::InvalidIssuer);
        }

        // Intermediate:
        //   Basic Constraints: critical
        //     CA:TRUE
        //     pathlen:0  // indicates no subordinate CA's

        let (_critical, basic_constraints) = authority
            .tbs_certificate
            .get::<BasicConstraints>()
            .map_err(|_err| X509VerificationError::ExtensionFailure)?
            .ok_or(X509VerificationError::BasicConstraintsNotPresent)?;

        if !basic_constraints.ca {
            return Err(X509VerificationError::CaNotMarkedAsSuch);
        }

        if let Some(ca_pathlen) = basic_constraints.path_len_constraint {
            // The current depth of the validation path exceeds that of the
            // allowed path length of the certificate.
            if path_length > ca_pathlen {
                return Err(X509VerificationError::PathLengthExceeded);
            }
        }

        let (_critical, key_usage) = authority
            .tbs_certificate
            .get::<KeyUsage>()
            .map_err(|_err| X509VerificationError::ExtensionFailure)?
            .ok_or(X509VerificationError::KeyUsageNotPresent)?;

        if !key_usage.key_cert_sign() {
            return Err(X509VerificationError::KeyUsageNotValid);
        }

        // Valid time range.
        let not_before = authority
            .tbs_certificate
            .validity
            .not_before
            .to_unix_duration();

        if not_before > current_time {
            return Err(X509VerificationError::NotBefore);
        }

        let not_after = authority
            .tbs_certificate
            .validity
            .not_after
            .to_unix_duration();

        if current_time > not_after {
            return Err(X509VerificationError::NotAfter);
        }

        // Now validate the signature of the certificate_to_validate
        if &certificate_to_validate.signature_algorithm != &authority.tbs_certificate.signature {
            return Err(X509VerificationError::SignatureAlgorithmMismatch);
        }

        let cert_to_validate_data = certificate_to_validate
            .tbs_certificate
            .to_der()
            .map_err(|_err| X509VerificationError::CertificateSerialisation)?;

        let cert_to_validate_signature = certificate_to_validate
            .signature
            .as_bytes()
            .ok_or(X509VerificationError::DerSignatureInvalid)?;

        verify_signature(
            &cert_to_validate_data,
            cert_to_validate_signature,
            authority,
        )?;

        Ok(())
    }

    fn locate_authority_certificate(
        &self,
        certificate_to_validate: &Certificate,
    ) -> Result<&Certificate, X509VerificationError> {
        self.store
            .iter()
            .find(|ca_cert| {
                ca_cert.tbs_certificate.subject == certificate_to_validate.tbs_certificate.issuer
            })
            .ok_or(X509VerificationError::NoMatchingIssuer)
    }
}

pub fn verify_signature(
    data: &[u8],
    signature: &[u8],
    certificate: &Certificate,
) -> Result<(), X509VerificationError> {
    let subject_public_key_info = certificate
        .tbs_certificate
        .subject_public_key_info
        .owned_to_ref();

    match certificate.tbs_certificate.signature.oid {
        oiddb::rfc5912::ECDSA_WITH_SHA_256 => {
            let signature = EcdsaP256DerSignature::try_from(signature)
                .map_err(|_err| X509VerificationError::DerSignatureInvalid)?;

            let verifier = EcdsaP256PublicKey::try_from(subject_public_key_info)
                .map(EcdsaP256VerifyingKey::from)
                .map_err(|_err| X509VerificationError::VerifyingKeyFromSpki)?;

            verifier
                .verify(data, &signature)
                .map_err(|_err| X509VerificationError::SignatureVerificationFailed)?;
        }
        oiddb::rfc5912::ECDSA_WITH_SHA_384 => {
            let signature = EcdsaP384DerSignature::try_from(signature)
                .map_err(|_err| X509VerificationError::DerSignatureInvalid)?;

            let verifier = EcdsaP384PublicKey::try_from(subject_public_key_info)
                .map(EcdsaP384VerifyingKey::from)
                .map_err(|_err| X509VerificationError::VerifyingKeyFromSpki)?;

            verifier
                .verify(data, &signature)
                .map_err(|_err| X509VerificationError::SignatureVerificationFailed)?;
        }
        oiddb::rfc5912::SHA_256_WITH_RSA_ENCRYPTION => {
            let signature = RS256Signature::try_from(signature)
                .map_err(|_err| X509VerificationError::DerSignatureInvalid)?;

            let verifier = RS256PublicKey::try_from(subject_public_key_info)
                .map(RS256VerifyingKey::new)
                .map_err(|_err| X509VerificationError::VerifyingKeyFromSpki)?;

            verifier
                .verify(data, &signature)
                .map_err(|_err| X509VerificationError::SignatureVerificationFailed)?;
        }
        algo_oid => {
            error!(?algo_oid);
            return Err(X509VerificationError::SignatureAlgorithmNotImplemented);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::X509Store;
    use crate::ecdsa_p384::{
        EcdsaP384PublicKey,
        // EcdsaP384DerSignature,
        EcdsaP384Signature,
        EcdsaP384VerifyingKey,
    };
    use crate::test_ca::*;
    use crate::traits::{DecodePem, Signer, Verifier};
    use crate::x509::{Certificate, Name, Time};
    use der::referenced::OwnedToRef;
    use std::str::FromStr;
    use std::time::Duration;
    use std::time::SystemTime;

    #[test]
    fn x509_chain_verify_basic() {
        let _ = tracing_subscriber::fmt::try_init();

        let now = SystemTime::now();
        let not_before = Time::try_from(now).unwrap();
        let not_after = Time::try_from(now + Duration::new(3600, 0)).unwrap();

        let (root_signing_key, root_ca_cert) = build_test_ca_root(not_before, not_after);

        let (int_signing_key, int_ca_cert) =
            build_test_ca_int(not_before, not_after, &root_signing_key, &root_ca_cert);

        let subject = Name::from_str("CN=localhost").unwrap();
        let (server_key, server_csr) = build_test_csr(subject);

        let server_cert = test_ca_sign_server_csr(
            not_before,
            not_after,
            &server_csr,
            &int_signing_key,
            &int_ca_cert,
        );

        // Also sign some data to validate.
        let test_data = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

        let test_data_signature: EcdsaP384Signature = server_key
            .try_sign(&test_data)
            // .map(|sig: EcdsaP384Signature | sig.to_der())
            .expect("Unable to sign test data");

        // Certs setup, validate now.
        let ca_store = X509Store::new(&[&root_ca_cert]);

        let leaf = &server_cert;
        let chain = [&int_ca_cert];

        assert_eq!(ca_store.verify(leaf, &chain, now), Ok(()));

        // Now validate our data signature.
        let subject_public_key_info = server_cert
            .tbs_certificate
            .subject_public_key_info
            .owned_to_ref();

        let verifier = EcdsaP384PublicKey::try_from(subject_public_key_info)
            .map(EcdsaP384VerifyingKey::from)
            .unwrap();

        verifier.verify(&test_data, &test_data_signature).unwrap();
    }

    #[test]
    fn x509_chain_verify_rsa_fido_mds() {
        let _ = tracing_subscriber::fmt::try_init();

        let global_sign_root_cert = Certificate::from_pem(GLOBAL_SIGN_ROOT).unwrap();
        let mds_cert = Certificate::from_pem(FIDO_MDS).unwrap();

        let ca_store = X509Store::new(&[&global_sign_root_cert]);

        let now = SystemTime::now();
        let leaf = &mds_cert;
        let chain = [];

        assert_eq!(ca_store.verify(leaf, &chain, now), Ok(()));
    }

    #[test]
    fn x509_chain_verify_rsa_yubico_u2f() {
        let _ = tracing_subscriber::fmt::try_init();

        let yubico_u2f_root_cert = Certificate::from_pem(YUBICO_U2F_ROOT).unwrap();
        let yubico_device_attest = Certificate::from_pem(YUBICO_DEVICE_ATTEST).unwrap();

        let ca_store = X509Store::new(&[&yubico_u2f_root_cert]);

        let now = SystemTime::now();
        let leaf = &yubico_device_attest;
        let chain = [];

        assert_eq!(ca_store.verify(leaf, &chain, now), Ok(()));
    }

    const YUBICO_U2F_ROOT: &str = r#"-----BEGIN CERTIFICATE-----
MIIDHjCCAgagAwIBAgIEG0BT9zANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZ
dWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAw
MDBaGA8yMDUwMDkwNDAwMDAwMFowLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290
IENBIFNlcmlhbCA0NTcyMDA2MzEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQC/jwYuhBVlqaiYWEMsrWFisgJ+PtM91eSrpI4TK7U53mwCIawSDHy8vUmk
5N2KAj9abvT9NP5SMS1hQi3usxoYGonXQgfO6ZXyUA9a+KAkqdFnBnlyugSeCOep
8EdZFfsaRFtMjkwz5Gcz2Py4vIYvCdMHPtwaz0bVuzneueIEz6TnQjE63Rdt2zbw
nebwTG5ZybeWSwbzy+BJ34ZHcUhPAY89yJQXuE0IzMZFcEBbPNRbWECRKgjq//qT
9nmDOFVlSRCt2wiqPSzluwn+v+suQEBsUjTGMEd25tKXXTkNW21wIWbxeSyUoTXw
LvGS6xlwQSgNpk2qXYwf8iXg7VWZAgMBAAGjQjBAMB0GA1UdDgQWBBQgIvz0bNGJ
hjgpToksyKpP9xv9oDAPBgNVHRMECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBBjAN
BgkqhkiG9w0BAQsFAAOCAQEAjvjuOMDSa+JXFCLyBKsycXtBVZsJ4Ue3LbaEsPY4
MYN/hIQ5ZM5p7EjfcnMG4CtYkNsfNHc0AhBLdq45rnT87q/6O3vUEtNMafbhU6kt
hX7Y+9XFN9NpmYxr+ekVY5xOxi8h9JDIgoMP4VB1uS0aunL1IGqrNooL9mmFnL2k
LVVee6/VR6C5+KSTCMCWppMuJIZII2v9o4dkoZ8Y7QRjQlLfYzd3qGtKbw7xaF1U
sG/5xUb/Btwb2X2g4InpiB/yt/3CpQXpiWX/K4mBvUKiGn05ZsqeY1gx4g0xLBqc
U9psmyPzK+Vsgw2jeRQ5JlKDyqE0hebfC1tvFu0CCrJFcw==
-----END CERTIFICATE-----"#;

    const YUBICO_DEVICE_ATTEST: &str = r#"-----BEGIN CERTIFICATE-----
MIICvTCCAaWgAwIBAgIEGKxGwDANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZ
dWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAw
MDBaGA8yMDUwMDkwNDAwMDAwMFowbjELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1
YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEnMCUG
A1UEAwweWXViaWNvIFUyRiBFRSBTZXJpYWwgNDEzOTQzNDg4MFkwEwYHKoZIzj0C
AQYIKoZIzj0DAQcDQgAEeeo7LHxJcBBiIwzSP+tg5SkxcdSD8QC+hZ1rD4OXAwG1
Rs3Ubs/K4+PzD4Hp7WK9Jo1MHr03s7y+kqjCrutOOqNsMGowIgYJKwYBBAGCxAoC
BBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjcwEwYLKwYBBAGC5RwCAQEEBAMCBSAwIQYL
KwYBBAGC5RwBAQQEEgQQy2lIHo/3QDmT7AonKaFUqDAMBgNVHRMBAf8EAjAAMA0G
CSqGSIb3DQEBCwUAA4IBAQCXnQOX2GD4LuFdMRx5brr7Ivqn4ITZurTGG7tX8+a0
wYpIN7hcPE7b5IND9Nal2bHO2orh/tSRKSFzBY5e4cvda9rAdVfGoOjTaCW6FZ5/
ta2M2vgEhoz5Do8fiuoXwBa1XCp61JfIlPtx11PXm5pIS2w3bXI7mY0uHUMGvxAz
ta74zKXLslaLaSQibSKjWKt9h+SsXy4JGqcVefOlaQlJfXL1Tga6wcO0QTu6Xq+U
w7ZPNPnrpBrLauKDd202RlN4SP7ohL3d9bG6V5hUz/3OusNEBZUn5W3VmPj1ZnFa
vkMB3RkRMOa58MZAORJT4imAPzrvJ0vtv94/y71C6tZ5
-----END CERTIFICATE-----"#;

    const GLOBAL_SIGN_ROOT: &str = r#"-----BEGIN CERTIFICATE-----
MIIEYTCCA0mgAwIBAgIOSKQC3SeSDaIINJ3RmXswDQYJKoZIhvcNAQELBQAwTDEg
MB4GA1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjMxEzARBgNVBAoTCkdsb2Jh
bFNpZ24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMTYwOTIxMDAwMDAwWhcNMjYw
OTIxMDAwMDAwWjBiMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBu
di1zYTE4MDYGA1UEAxMvR2xvYmFsU2lnbiBFeHRlbmRlZCBWYWxpZGF0aW9uIENB
IC0gU0hBMjU2IC0gRzMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCr
awNnVNXcEfvFohPBjBkn3BB04mGDPfqO24+lD+SpvkY/Ar5EpAkcJjOfR0iBFYhW
N80HzpXYy2tIA7mbXpKu2JpmYdU1xcoQpQK0ujE/we+vEDyjyjmtf76LLqbOfuq3
xZbSqUqAY+MOvA67nnpdawvkHgJBFVPnxui45XH4BwTwbtDucx+Mo7EK4mS0Ti+P
1NzARxFNCUFM8Wxc32wxXKff6WU4TbqUx/UJm485ttkFqu0Ox4wTUUbn0uuzK7yV
3Y986EtGzhKBraMH36MekSYlE473GqHetRi9qbNG5pM++Sa+WjR9E1e0Yws16CGq
smVKwAqg4uc43eBTFUhVAgMBAAGjggEpMIIBJTAOBgNVHQ8BAf8EBAMCAQYwEgYD
VR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU3bPnbagu6MVObs905nU8lBXO6B0w
HwYDVR0jBBgwFoAUj/BLf6guRSSuTVD6Y5qL3uLdG7wwPgYIKwYBBQUHAQEEMjAw
MC4GCCsGAQUFBzABhiJodHRwOi8vb2NzcDIuZ2xvYmFsc2lnbi5jb20vcm9vdHIz
MDYGA1UdHwQvMC0wK6ApoCeGJWh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vcm9v
dC1yMy5jcmwwRwYDVR0gBEAwPjA8BgRVHSAAMDQwMgYIKwYBBQUHAgEWJmh0dHBz
Oi8vd3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMA0GCSqGSIb3DQEBCwUA
A4IBAQBVaJzl0J/i0zUV38iMXIQ+Q/yht+JZZ5DW1otGL5OYV0LZ6ZE6xh+WuvWJ
J4hrDbhfo6khUEaFtRUnurqzutvVyWgW8msnoP0gtMZO11cwPUMUuUV8iGyIOuIB
0flo6G+XbV74SZuR5v5RAgqgGXucYUPZWvv9AfzMMQhRQkr/MO/WR2XSdiBrXHoD
L2xk4DmjA4K6iPI+1+qMhyrkUM/2ZEdA8ldqwl8nQDkKS7vq6sUZ5LPVdfpxJZZu
5JBj4y7FNFTVW1OMlCUvwt5H8aFgBMLFik9xqK6JFHpYxYmf4t2sLLxN0LlCthJE
abvp10ZlOtfu8hL5gCXcxnwGxzSb
-----END CERTIFICATE-----"#;

    const FIDO_MDS: &str = r#"-----BEGIN CERTIFICATE-----
MIIHGTCCBgGgAwIBAgIMIa7sY/5SFH8UYph5MA0GCSqGSIb3DQEBCwUAMGIxCzAJ
BgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTgwNgYDVQQDEy9H
bG9iYWxTaWduIEV4dGVuZGVkIFZhbGlkYXRpb24gQ0EgLSBTSEEyNTYgLSBHMzAe
Fw0yNDA2MjYyMDE3MDRaFw0yNTA3MjgyMDE3MDNaMIHSMR0wGwYDVQQPDBRQcml2
YXRlIE9yZ2FuaXphdGlvbjEQMA4GA1UEBRMHMzQ1NDI4NDETMBEGCysGAQQBgjc8
AgEDEwJVUzEbMBkGCysGAQQBgjc8AgECEwpDYWxpZm9ybmlhMQswCQYDVQQGEwJV
UzEPMA0GA1UECBMGT3JlZ29uMRIwEAYDVQQHEwlCZWF2ZXJ0b24xHDAaBgNVBAoT
E0ZJRE8gQUxMSUFOQ0UsIElOQy4xHTAbBgNVBAMTFG1kcy5maWRvYWxsaWFuY2Uu
b3JnMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6AskoQ0bFp93JQQd
p1b8nFCmB67dTNUptwkKtnHj0Y18DWopH8CKORM1LjAHyjMTPoOGXb5/rt1wDfOK
b0chqSG9llrBzp/N0BuLL0ZFyZEAYt4th8Y0Ooc3FQtXZ99T6HNW+fmXaLbYxxnG
nsxAxjVQmHwCZBnx+WPKgi6BqaYcY05M8uzWkgSp1nE4jD+JQ9HN0HSFhzHe3LW4
v0th2Jz1OQmMhwia0SD/V6YXIqkXkqmmFenhCfSG+/LiLgWxmeIwApJ5oe10Dvmi
JYeaaFkgbEc/b7/6PMaa4X/0aZZ1J7C0EHvn5lUHb8hfBbzGhsBKOpQW1uOhiK+y
I9oKQQIDAQABo4IDXDCCA1gwDgYDVR0PAQH/BAQDAgWgMAwGA1UdEwEB/wQCMAAw
gZYGCCsGAQUFBwEBBIGJMIGGMEcGCCsGAQUFBzAChjtodHRwOi8vc2VjdXJlLmds
b2JhbHNpZ24uY29tL2NhY2VydC9nc2V4dGVuZHZhbHNoYTJnM3IzLmNydDA7Bggr
BgEFBQcwAYYvaHR0cDovL29jc3AyLmdsb2JhbHNpZ24uY29tL2dzZXh0ZW5kdmFs
c2hhMmczcjMwVQYDVR0gBE4wTDBBBgkrBgEEAaAyAQEwNDAyBggrBgEFBQcCARYm
aHR0cHM6Ly93d3cuZ2xvYmFsc2lnbi5jb20vcmVwb3NpdG9yeS8wBwYFZ4EMAQEw
RQYDVR0fBD4wPDA6oDigNoY0aHR0cDovL2NybC5nbG9iYWxzaWduLmNvbS9ncy9n
c2V4dGVuZHZhbHNoYTJnM3IzLmNybDAfBgNVHREEGDAWghRtZHMuZmlkb2FsbGlh
bmNlLm9yZzAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwHwYDVR0jBBgw
FoAU3bPnbagu6MVObs905nU8lBXO6B0wHQYDVR0OBBYEFMaN4X1b9AHuWDPJK1AY
dg2MQGhxMIIBfwYKKwYBBAHWeQIEAgSCAW8EggFrAWkAdgAS8U40vVNyTIQGGcOP
P3oT+Oe1YoeInG0wBYTr5YYmOgAAAZBWMd/sAAAEAwBHMEUCIQDLehoLcAsQrMOG
NzpCOEewntO7/FGYjM1BJwLaooEZeAIgKXVD02S4x8C+5zfxgVFbin3VHlP4l+FU
925i66QhsVoAdgAN4fIwK9MNwUBiEgnqVS78R3R8sdfpMO8OQh60fk6qNAAAAZBW
Md0DAAAEAwBHMEUCIFQEuBdgAXVF0joEul6oLwpIrz818XXZWbtg3LWJvInhAiEA
iibo7o9oSc8UUnUUf6/4QhxBZ1DGGN34Qv1t8Cp+a5UAdwDm0jFjQHeMwRBBBtdx
uc7B0kD2loSG+7qHMh39HjeOUAAAAZBWMd8eAAAEAwBIMEYCIQDQZGnntKA3LnHj
V76+Fq55Nypv1BsHZLfhG736TcspLwIhANHF8kMePNAIooXltURI5i+sNF96x2zR
PA6Ly2D/DezDMA0GCSqGSIb3DQEBCwUAA4IBAQBxWM7olfKF6bhJ8SzVKIKgfeV+
YDqQS1Z9r453X5ZFv3jfD74uhsGjg2fI5vMulZzlFwXNTta0bf0TzaC0rkhuAcnc
Rfi0rk9MmI6HMuG4qaEO+6JJxst/OH/1k/GC8gh2MgwX6Aq9b33kaMTEnGeByFEH
Qf/4ZcuhoOkVeQ7MX+p0BNdaNdp6v6au4WDf0JJgTPPV//VJykqOCV6zgTt3hra0
HR9+f1CMFvtSC1OpP197c7XGNdK2Rnn/6Z2y7Ak9G3iYhGhS/Ssz9zsOUTi7b+SY
ywLlY2y0vY1svPUSJEWjhMtVDL9b2/DvIhNqp0kGCiXCGmtzW5DxgXE1ckkh
-----END CERTIFICATE-----"#;
}
