#![deny(warnings)]
#![allow(dead_code)]
#![warn(unused_extern_crates)]
// Enable some groups of clippy lints.
#![deny(clippy::suspicious)]
#![deny(clippy::perf)]
// Specific lints to enforce.
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]
#![deny(clippy::disallowed_types)]
#![deny(clippy::manual_let_else)]
#![allow(clippy::unreachable)]

pub mod aes128;
pub mod aes128gcm;
pub mod aes128kw;
pub mod aes256;
pub mod aes256cbc;
pub mod aes256cts;
pub mod aes256gcm;
pub mod aes256kw;
pub mod ec;
pub mod ecdh;
pub mod ecdh_p256;
pub mod ecdsa_p256;
pub mod ecdsa_p384;
pub mod ecdsa_p521;
pub mod hkdf_s256;
pub mod hmac_s1;
pub mod hmac_s256;
pub mod hmac_s512;
pub mod nist_sp800_108_kdf_hmac_sha256;
pub mod pkcs8;
pub mod rsa;
pub mod s256;
pub mod s384;
pub mod s512;
pub mod sha1;
pub mod traits;
pub mod x509;

pub use argon2;
pub use cipher::block_padding;
pub use der;
pub use hex;
pub use md5;
pub use pbkdf2;
pub use rand;
pub use spki;
pub use zeroize;

pub mod prelude {}
