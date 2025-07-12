use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::SharedSecret as SharedSecretTrait;

use crate::traits::Kem;

pub struct Kyber768Kem;

impl Kem for Kyber768Kem {
    type PublicKey = kyber768::PublicKey;
    type SecretKey = kyber768::SecretKey;
    type Ciphertext = kyber768::Ciphertext;
    type SharedSecret = Vec<u8>;

    fn generate_keypair() -> (Self::PublicKey, Self::SecretKey) {
        kyber768::keypair()
    }

    fn encapsulate(pk: &Self::PublicKey) -> (Self::Ciphertext, Self::SharedSecret) {
        let (ss, ct) = kyber768::encapsulate(pk);
        (ct, ss.as_bytes().to_vec())
    }

    fn decapsulate(sk: &Self::SecretKey, ct: &Self::Ciphertext) -> Self::SharedSecret {
        let ss = kyber768::decapsulate(ct, sk);
        ss.as_bytes().to_vec()
    }
}
