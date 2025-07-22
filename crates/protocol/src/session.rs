use crypto::aead;
use crypto::hkdf::SessionKeys;

use crate::messages::AppData;

pub struct SecureChannel {
    keys: SessionKeys,
    transcript: [u8; 32],
    is_client: bool,
    send_seq: u64,
    recv_seq: u64,
}

#[derive(Debug)]
pub enum ChannelError {
    DecryptionFailed,
    ReplayDetected,
    InvalidSequence,
}

fn build_aad(seq: u64, transcript: &[u8; 32]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(8 + 32);
    aad.extend_from_slice(&seq.to_be_bytes());
    aad.extend_from_slice(transcript);
    aad
}

impl SecureChannel {
    pub fn new(keys: SessionKeys, transcript: [u8; 32], is_client: bool) -> Self {
        Self {
            keys,
            transcript,
            is_client,
            send_seq: 0,
            recv_seq: 0,
        }
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> AppData {
        self.send_seq += 1;
        let seq = self.send_seq;

        let (key, nonce_base) = if self.is_client {
            (&self.keys.k_client_to_server, &self.keys.nonce_base_c2s)
        } else {
            (&self.keys.k_server_to_client, &self.keys.nonce_base_s2c)
        };

        let aad = build_aad(seq, &self.transcript);
        let ciphertext = aead::encrypt(key, nonce_base, seq, &aad, plaintext);

        AppData { seq, ciphertext }
    }

    pub fn decrypt(&mut self, app_data: &AppData) -> Result<Vec<u8>, ChannelError> {
        if app_data.seq <= self.recv_seq {
            return Err(ChannelError::ReplayDetected);
        }

        let (key, nonce_base) = if self.is_client {
            (&self.keys.k_server_to_client, &self.keys.nonce_base_s2c)
        } else {
            (&self.keys.k_client_to_server, &self.keys.nonce_base_c2s)
        };

        let aad = build_aad(app_data.seq, &self.transcript);
        let plaintext = aead::decrypt(key, nonce_base, app_data.seq, &aad, &app_data.ciphertext)
            .map_err(|_| ChannelError::DecryptionFailed)?;

        self.recv_seq = app_data.seq;
        Ok(plaintext)
    }

    pub fn next_recv_seq(&self) -> u64 {
        self.recv_seq + 1
    }
}
