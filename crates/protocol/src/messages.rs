use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientHello {
    pub version: u8,
    pub kyber_pk: Vec<u8>,
    pub x25519_pk: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerHello {
    pub kyber_ct: Vec<u8>,
    pub x25519_pk: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppData {
    pub seq: u64,
    pub ciphertext: Vec<u8>,
}

impl ClientHello {
    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("serialization should not fail")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MessageError> {
        postcard::from_bytes(bytes).map_err(|_| MessageError::InvalidFormat)
    }
}

impl ServerHello {
    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("serialization should not fail")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MessageError> {
        postcard::from_bytes(bytes).map_err(|_| MessageError::InvalidFormat)
    }
}

impl AppData {
    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("serialization should not fail")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MessageError> {
        postcard::from_bytes(bytes).map_err(|_| MessageError::InvalidFormat)
    }
}

#[derive(Debug)]
pub enum MessageError {
    InvalidFormat,
}
