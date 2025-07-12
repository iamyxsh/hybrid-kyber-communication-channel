use hybrid_kyber_crypto::kyber::Kyber768Kem;
use hybrid_kyber_crypto::traits::Kem;

#[test]
fn test_encapsulate_decapsulate() {
    let (pk, sk) = Kyber768Kem::generate_keypair();
    let (ct, shared_secret_1) = Kyber768Kem::encapsulate(&pk);
    let shared_secret_2 = Kyber768Kem::decapsulate(&sk, &ct);
    assert_eq!(shared_secret_1, shared_secret_2);
}
