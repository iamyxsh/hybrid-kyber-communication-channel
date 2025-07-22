use sha2::{Digest, Sha256};

use crate::messages::{ClientHello, ServerHello};

pub fn compute_transcript(client_hello: &ClientHello, server_hello: &ServerHello) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(&client_hello.to_bytes());
    hasher.update(&server_hello.to_bytes());
    hasher.finalize().into()
}
