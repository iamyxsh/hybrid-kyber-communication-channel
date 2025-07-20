use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce, Tag};

pub const TAG_SIZE: usize = 16;

#[derive(Debug)]
pub struct AeadError;

fn compute_nonce(nonce_base: &[u8; 12], seq: u64) -> [u8; 12] {
    let mut nonce = *nonce_base;
    let seq_bytes = seq.to_be_bytes();
    for i in 0..8 {
        nonce[4 + i] ^= seq_bytes[i];
    }
    nonce
}

pub fn encrypt(
    key: &[u8; 32],
    nonce_base: &[u8; 12],
    seq: u64,
    aad: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    let nonce_bytes = compute_nonce(nonce_base, seq);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let cipher = ChaCha20Poly1305::new_from_slice(key).expect("valid key length");

    let mut buffer = plaintext.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(nonce, aad, &mut buffer)
        .expect("encryption should not fail");

    buffer.extend_from_slice(&tag);
    buffer
}

pub fn decrypt(
    key: &[u8; 32],
    nonce_base: &[u8; 12],
    seq: u64,
    aad: &[u8],
    ciphertext_with_tag: &[u8],
) -> Result<Vec<u8>, AeadError> {
    if ciphertext_with_tag.len() < TAG_SIZE {
        return Err(AeadError);
    }

    let nonce_bytes = compute_nonce(nonce_base, seq);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let cipher = ChaCha20Poly1305::new_from_slice(key).expect("valid key length");

    let ct_len = ciphertext_with_tag.len() - TAG_SIZE;
    let mut buffer = ciphertext_with_tag[..ct_len].to_vec();
    let tag = Tag::from_slice(&ciphertext_with_tag[ct_len..]);

    cipher
        .decrypt_in_place_detached(nonce, aad, &mut buffer, tag)
        .map_err(|_| AeadError)?;

    Ok(buffer)
}
