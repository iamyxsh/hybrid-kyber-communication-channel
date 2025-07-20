use hybrid_kyber_crypto::aead::{decrypt, encrypt};

#[test]
fn test_encrypt_decrypt_roundtrip() {
    let key = [0x42u8; 32];
    let nonce_base = [0x01u8; 12];
    let seq = 1u64;
    let aad = b"session-context";
    let plaintext = b"hello, post-quantum world!";

    let ciphertext = encrypt(&key, &nonce_base, seq, aad, plaintext);
    let decrypted = decrypt(&key, &nonce_base, seq, aad, &ciphertext).unwrap();

    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_wrong_seq_fails() {
    let key = [0x42u8; 32];
    let nonce_base = [0x01u8; 12];
    let aad = b"session-context";
    let plaintext = b"secret message";

    let ciphertext = encrypt(&key, &nonce_base, 1, aad, plaintext);
    let result = decrypt(&key, &nonce_base, 2, aad, &ciphertext);

    assert!(result.is_err());
}

#[test]
fn test_tampered_ciphertext_fails() {
    let key = [0x42u8; 32];
    let nonce_base = [0x01u8; 12];
    let seq = 1u64;
    let aad = b"session-context";
    let plaintext = b"secret message";

    let mut ciphertext = encrypt(&key, &nonce_base, seq, aad, plaintext);
    ciphertext[0] ^= 0xFF;

    let result = decrypt(&key, &nonce_base, seq, aad, &ciphertext);
    assert!(result.is_err());
}
