mod test_ca;

use crate::test_ca::*;
use crypto_glue::ecdsa_p384::{
    EcdsaP384PublicKey,
    // EcdsaP384DerSignature,
    EcdsaP384Signature,
    EcdsaP384VerifyingKey,
};
use crypto_glue::traits::{DecodePem, Signer, Verifier};
use crypto_glue::x509::{Certificate, Name, Time, X509Display, X509Store};
use der::referenced::OwnedToRef;
use std::str::FromStr;
use std::time::Duration;
use std::time::SystemTime;

#[cfg(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none")))]
use wasm_bindgen_test::*;
#[cfg(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none")))]
wasm_bindgen_test_configure!(run_in_browser);

#[test]
#[cfg_attr(
    all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none")),
    wasm_bindgen_test
)]
fn x509_chain_verify_basic() {
    let _ = tracing_subscriber::fmt::try_init();

    let now = now();
    let not_before = Time::try_from(now).expect("Failed to convert SystemTime to Time");
    let not_after =
        Time::try_from(now + Duration::new(3600, 0)).expect("Failed to convert SystemTime to Time");

    let (root_signing_key, root_ca_cert) = build_test_ca_root(not_before, not_after);

    let (int_signing_key, int_ca_cert) =
        build_test_ca_int(not_before, not_after, &root_signing_key, &root_ca_cert);

    let subject = Name::from_str("CN=localhost").expect("Failed to parse subject name");
    let (server_key, server_csr) = build_test_csr(&subject);

    let server_cert = test_ca_sign_server_csr(
        not_before,
        not_after,
        &server_csr,
        &int_signing_key,
        &int_ca_cert,
    );

    tracing::debug!(cert = %X509Display::from(&server_cert));

    // Also sign some data to validate.
    let test_data = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

    let test_data_signature: EcdsaP384Signature = server_key
        .try_sign(&test_data)
        // .map(|sig: EcdsaP384Signature | sig.to_der())
        .expect("Unable to sign test data");

    // Certs setup, validate now.
    let ca_store = X509Store::new(&[root_ca_cert]);

    let leaf = &server_cert;
    let chain = [int_ca_cert];

    assert!(ca_store.verify(leaf, &chain, now).is_ok());

    // Now validate our data signature.
    let subject_public_key_info = server_cert
        .tbs_certificate()
        .subject_public_key_info()
        .owned_to_ref();

    let verifier = EcdsaP384PublicKey::try_from(subject_public_key_info)
        .map(EcdsaP384VerifyingKey::from)
        .expect("Failed to create EcdsaP384VerifyingKey");

    verifier
        .verify(&test_data, &test_data_signature)
        .expect("Failed to verify test data signature");
}

#[test]
#[cfg_attr(
    all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none")),
    wasm_bindgen_test
)]
fn x509_chain_verify_rsa_fido_mds() {
    let _ = tracing_subscriber::fmt::try_init();

    let global_sign_root_cert =
        Certificate::from_pem(GLOBAL_SIGN_ROOT).expect("Failed to parse GlobalSign Root cert");
    let mds_cert = Certificate::from_pem(FIDO_MDS).expect("Failed to parse FIDO MDS cert");

    let ca_store = X509Store::new(&[global_sign_root_cert]);

    // To check before expiry
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1753733820);
    let leaf = &mds_cert;
    let chain = [];

    let result = ca_store.verify(leaf, &chain, now);
    assert!(result.is_ok());

    // Check expiry causes this to be invalid
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1753733825);
    let result = ca_store.verify(leaf, &chain, now);
    assert!(result.is_err());
}

#[test]
#[cfg_attr(
    all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none")),
    wasm_bindgen_test
)]
fn x509_chain_verify_rsa_yubico_u2f() {
    let _ = tracing_subscriber::fmt::try_init();

    let yubico_u2f_root_cert =
        Certificate::from_pem(YUBICO_U2F_ROOT).expect("Failed to parse Yubico U2F Root cert");
    let yubico_device_attest = Certificate::from_pem(YUBICO_DEVICE_ATTEST)
        .expect("Failed to parse Yubico Device Attest cert");

    let ca_store = X509Store::new(&[yubico_u2f_root_cert]);

    let now = now();
    let leaf = &yubico_device_attest;
    let chain = [];

    assert!(ca_store.verify(leaf, &chain, now).is_ok());
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
