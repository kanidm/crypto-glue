
use x509_cert::ext::pkix::name::GeneralName;

use std::fmt;
use std::fmt::Write;
use x509_cert::der::referenced::OwnedToRef;
use x509_cert::der::Decode;
use x509_cert::ext::pkix::AuthorityKeyIdentifier;
use x509_cert::ext::pkix::BasicConstraints;
use x509_cert::ext::pkix::ExtendedKeyUsage;
use x509_cert::ext::pkix::KeyUsage;
use x509_cert::ext::pkix::SubjectKeyIdentifier;
use x509_cert::spki::SubjectPublicKeyInfoRef;

use const_oid::AssociatedOid;

fn write_bytes_pretty(indent: &str, bytes: &[u8], f: &mut String) -> Result<(), fmt::Error> {
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

fn general_name_pretty(g_name: &GeneralName, f: &mut String) -> Result<(), fmt::Error> {
    match g_name {
        GeneralName::OtherName(_othername) => {
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
        GeneralName::EdiPartyName(_edi_party_name) => {
            write!(f, "EdiParty: TODO")
        }
        GeneralName::UniformResourceIdentifier(ia5str) => {
            write!(f, "URI: {ia5str}")
        }
        GeneralName::IpAddress(_octet_str) => {
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
    // let indent_five = "          ";

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
    write!(
        f,
        "{indent_two}Version: {:?}\n",
        cert.tbs_certificate.version
    )?;

    // Serial
    write!(f, "{indent_two}Serial:\n")?;
    write_bytes_pretty(
        indent_three,
        cert.tbs_certificate.serial_number.as_bytes(),
        f,
    )?;
    write!(f, "\n")?;

    // Subject
    write!(f, "{indent_two}Subject: {}\n", cert.tbs_certificate.subject)?;

    // Issuer
    write!(f, "{indent_two}Issuer: {}\n", cert.tbs_certificate.issuer)?;

    // Issuer Unique Id
    if let Some(issuer_unique_id) = &cert.tbs_certificate.issuer_unique_id {
        write!(f, "{indent_two}Issuer Unique ID:\n")?;
        write_bytes_pretty(indent_three, issuer_unique_id.as_bytes().unwrap(), f)?;
        write!(f, "\n")?;
    }

    // Subject Unique Id
    if let Some(subject_unique_id) = &cert.tbs_certificate.subject_unique_id {
        write!(f, "{indent_two}Subject Unique ID:\n")?;
        write_bytes_pretty(indent_three, subject_unique_id.as_bytes().unwrap(), f)?;
        write!(f, "\n")?;
    }

    // Validity
    write!(f, "{indent_two}Validity\n")?;
    write!(
        f,
        "{indent_three}Not Before: {}\n",
        cert.tbs_certificate.validity.not_before
    )?;
    write!(
        f,
        "{indent_three}Not After: {}\n",
        cert.tbs_certificate.validity.not_after
    )?;

    // Signature Algorithm:
    write!(f, "{indent_two}Signature Algorithm: ")?;
    match &cert.tbs_certificate.signature.oid {
        &const_oid::db::rfc5912::ECDSA_WITH_SHA_256 => write!(f, "ecdsa-with-sha256")?,
        &const_oid::db::rfc5912::ECDSA_WITH_SHA_384 => write!(f, "ecdsa-with-sha384")?,
        &const_oid::db::rfc5912::ECDSA_WITH_SHA_512 => write!(f, "ecdsa-with-sha512")?,
        &const_oid::db::rfc5912::SHA_256_WITH_RSA_ENCRYPTION => {
            write!(f, "sha256-with-rsa-encryption")?
        }
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
    for extension in cert
        .tbs_certificate
        .extensions
        .iter()
        .flat_map(|exts| exts.iter())
    {
        match extension.extn_id {
            BasicConstraints::OID => {
                let bc = BasicConstraints::from_der(extension.extn_value.as_bytes())
                    .expect("Invalid Basic Constraints");
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
                let ski = SubjectKeyIdentifier::from_der(extension.extn_value.as_bytes())
                    .expect("Invalid Subject Key ID");

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
                let ku =
                    KeyUsage::from_der(extension.extn_value.as_bytes()).expect("Invalid Key Usage");

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
                let aki = AuthorityKeyIdentifier::from_der(extension.extn_value.as_bytes())
                    .expect("Invalid Authority Key ID");

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
                    write!(f, "\n")?;
                }
            }

            // Extended Key Usage
            // 2.5.29.37
            ExtendedKeyUsage::OID => {
                let eku = ExtendedKeyUsage::from_der(extension.extn_value.as_bytes())
                    .expect("Invalid Extended Key Usage");

                write!(f, "{indent_three}Authority Key Identifier:")?;
                if extension.critical {
                    write!(f, " critical")?;
                }
                write!(f, "\n")?;

                for oid in eku.as_ref().iter() {
                    write!(f, "{indent_four}")?;
                    match oid {
                        &const_oid::db::rfc5280::ID_KP_SERVER_AUTH => {
                            write!(f, "Server Authentication")?
                        }
                        &const_oid::db::rfc5280::ID_KP_CLIENT_AUTH => {
                            write!(f, "Client Authentication")?
                        }
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
        &const_oid::db::rfc5912::SHA_256_WITH_RSA_ENCRYPTION => {
            write!(f, "sha256-with-rsa-encryption")?
        }
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
