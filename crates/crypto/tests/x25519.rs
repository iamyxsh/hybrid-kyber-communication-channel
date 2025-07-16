use hybrid_kyber_crypto::traits::Kem;
use hybrid_kyber_crypto::x25519::X25519Kem;

#[test]
fn test_x25519_kem() {
    let (pk, sk) = X25519Kem::generate_keypair();
    let (ct, ss1) = X25519Kem::encapsulate(&pk);
    let ss2 = X25519Kem::decapsulate(&sk, &ct);
    assert_eq!(ss1, ss2);
}
