#[cfg(any(unix, windows))]
mod test_ca;

#[cfg(any(unix, windows))]
#[test]
fn rustls_mtls_basic() {
    use crate::test_ca::*;
    use crypto_glue::x509::X509Display;
    use elliptic_curve::SecretKey;
    use rustls::{
        self, RootCertStore,
        client::{ClientConfig, ClientConnection},
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
        server::{ServerConfig, ServerConnection},
    };
    use std::io::Read;
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::net::UnixStream;
    use std::str::FromStr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU16, Ordering};
    use std::time::Duration;
    #[cfg(windows)]
    use uds_windows::UnixStream;
    use x509_cert::der::Encode;
    use x509_cert::name::Name;
    use x509_cert::time::Time;

    // ========================
    // CA SETUP

    let now = now();
    let not_before = Time::try_from(now).expect("Failed to convert system time to X509 time");
    let not_after = Time::try_from(now + Duration::new(3600, 0))
        .expect("Failed to convert system time to X509 time");

    let (root_signing_key, root_ca_cert) = build_test_ca_root(not_before, not_after);

    eprintln!("{}", X509Display::from(&root_ca_cert));

    let subject = Name::from_str("CN=localhost").expect("Failed to parse subject name");

    let (server_key, server_csr) = build_test_csr(&subject);

    let server_cert = test_ca_sign_server_csr(
        not_before,
        not_after,
        &server_csr,
        &root_signing_key,
        &root_ca_cert,
    );

    eprintln!("{}", X509Display::from(&server_cert));

    // ========================
    use p384::pkcs8::EncodePrivateKey;
    let server_private_key_pkcs8_der = SecretKey::from(server_key)
        .to_pkcs8_der()
        .expect("Failed to encode server private key");

    let root_ca_cert_der = root_ca_cert
        .to_der()
        .expect("Failed to encode root CA certificate");
    let server_cert_der = server_cert
        .to_der()
        .expect("Failed to encode server certificate");

    let mut ca_roots = RootCertStore::empty();

    ca_roots
        .add(CertificateDer::from(root_ca_cert_der.clone()))
        .expect("Failed to add root CA certificate");

    let server_chain = vec![
        CertificateDer::from(server_cert_der),
        CertificateDer::from(root_ca_cert_der),
    ];

    let server_private_key: PrivateKeyDer =
        PrivatePkcs8KeyDer::from(server_private_key_pkcs8_der.as_bytes().to_vec()).into();

    // let provider = Arc::new(rustls_rustcrypto::provider());
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());

    let client_tls_config: Arc<_> = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("invalid protocol versions")
        .with_root_certificates(ca_roots)
        .with_no_client_auth()
        .into();

    let server_tls_config: Arc<_> = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("invalid protocol versions")
        .with_no_client_auth()
        .with_single_cert(server_chain, server_private_key)
        .map(Arc::new)
        .expect("bad certificate/key");

    let server_name = ServerName::try_from("localhost").expect("invalid DNS name");

    let (mut server_unix_stream, mut client_unix_stream) =
        UnixStream::pair().expect("Failed to create UnixStream pair");

    let atomic = Arc::new(AtomicU16::new(0));

    let atomic_t = atomic.clone();

    let handle = std::thread::spawn(move || {
        let mut client_connection = ClientConnection::new(client_tls_config, server_name)
            .expect("Failed to create client connection");

        let mut client = rustls::Stream::new(&mut client_connection, &mut client_unix_stream);

        client.write_all(b"hello").expect("Failed to write data");

        while atomic_t.load(Ordering::Relaxed) != 1 {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }

        println!("THREAD DONE");
    });

    let mut server_connection =
        ServerConnection::new(server_tls_config).expect("Failed to create server connection");

    server_connection
        .complete_io(&mut server_unix_stream)
        .expect("Failed to complete TLS handshake");

    server_connection
        .complete_io(&mut server_unix_stream)
        .expect("Failed to complete TLS handshake");

    let mut buf: [u8; 5] = [0; 5];
    server_connection
        .reader()
        .read_exact(&mut buf)
        .expect("Failed to read data");

    assert_eq!(&buf, b"hello");

    atomic.store(1, Ordering::Relaxed);

    // If the thread paniced, this will panic.
    handle.join().expect("Thread panicked");
}
