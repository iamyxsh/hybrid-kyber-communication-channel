use hkdf::Hkdf;
use rand::rngs::OsRng;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::traits::Kem;

const HKDF_INFO: &[u8] = b"x25519-kem";

pub struct X25519Kem;

impl Kem for X25519Kem {
    type PublicKey = PublicKey;
    type SecretKey = StaticSecret;
    type Ciphertext = [u8; 32];
    type SharedSecret = Vec<u8>;

    fn generate_keypair() -> (Self::PublicKey, Self::SecretKey) {
        let sk = StaticSecret::random_from_rng(OsRng);
        let pk = PublicKey::from(&sk);
        (pk, sk)
    }

    fn encapsulate(pk: &Self::PublicKey) -> (Self::Ciphertext, Self::SharedSecret) {
        let eph_sk = StaticSecret::random_from_rng(OsRng);
        let eph_pk = PublicKey::from(&eph_sk);
        let dh = eph_sk.diffie_hellman(pk);

        let mut okm = vec![0u8; 32];
        let hk = Hkdf::<Sha256>::new(None, dh.as_bytes());
        hk.expand(HKDF_INFO, &mut okm)
            .expect("valid output length");

        (eph_pk.to_bytes(), okm)
    }

    fn decapsulate(sk: &Self::SecretKey, ct: &Self::Ciphertext) -> Self::SharedSecret {
        let eph_pk = PublicKey::from(*ct);
        let dh = sk.diffie_hellman(&eph_pk);

        let mut okm = vec![0u8; 32];
        let hk = Hkdf::<Sha256>::new(None, dh.as_bytes());
        hk.expand(HKDF_INFO, &mut okm)
            .expect("valid output length");

        okm
    }
}
