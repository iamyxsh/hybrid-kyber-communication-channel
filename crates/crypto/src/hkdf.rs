use hkdf::Hkdf;
use sha2::Sha256;

const INFO: &[u8] = b"hybrid-pq-channel-v1";

pub struct SessionKeys {
    pub k_client_to_server: [u8; 32],
    pub k_server_to_client: [u8; 32],
    pub nonce_base_c2s: [u8; 12],
    pub nonce_base_s2c: [u8; 12],
}

/// Derive session keys from shared secrets and transcript
pub fn derive_session_keys(
    ss_pq: &[u8],
    ss_classical: &[u8],
    transcript: &[u8; 32],
) -> SessionKeys {
    let ikm = [ss_pq, ss_classical].concat();
    let hk = Hkdf::<Sha256>::new(Some(transcript), &ikm);

    let mut okm = [0u8; 88];
    hk.expand(INFO, &mut okm).expect("valid length");

    let mut k_client_to_server = [0u8; 32];
    let mut k_server_to_client = [0u8; 32];
    let mut nonce_base_c2s = [0u8; 12];
    let mut nonce_base_s2c = [0u8; 12];

    k_client_to_server.copy_from_slice(&okm[0..32]);
    k_server_to_client.copy_from_slice(&okm[32..64]);
    nonce_base_c2s.copy_from_slice(&okm[64..76]);
    nonce_base_s2c.copy_from_slice(&okm[76..88]);

    SessionKeys {
        k_client_to_server,
        k_server_to_client,
        nonce_base_c2s,
        nonce_base_s2c,
    }
}
