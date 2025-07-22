use crypto::hkdf::{derive_session_keys, SessionKeys};
use crypto::kyber::Kyber768Kem;
use crypto::traits::Kem;
use crypto::x25519::X25519Kem;
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _};

use crate::messages::{ClientHello, ServerHello};
use crate::transcript::compute_transcript;

const PROTOCOL_VERSION: u8 = 1;
const KYBER768_PK_SIZE: usize = 1184;
const KYBER768_CT_SIZE: usize = 1088;

pub struct ClientHandshakeState {
    pub client_hello: ClientHello,
    kyber_sk: <Kyber768Kem as Kem>::SecretKey,
    x25519_sk: <X25519Kem as Kem>::SecretKey,
    x25519_pk: <X25519Kem as Kem>::PublicKey,
}

pub struct Session {
    pub keys: SessionKeys,
    pub transcript: [u8; 32],
    pub is_client: bool,
}

#[derive(Debug)]
pub enum HandshakeError {
    InvalidVersion,
    InvalidKeySize,
    DecapsulationFailed,
}

pub fn generate_client_hello() -> (ClientHello, ClientHandshakeState) {
    let (kyber_pk, kyber_sk) = Kyber768Kem::generate_keypair();
    let (x25519_pk, x25519_sk) = X25519Kem::generate_keypair();

    let client_hello = ClientHello {
        version: PROTOCOL_VERSION,
        kyber_pk: kyber_pk.as_bytes().to_vec(),
        x25519_pk: x25519_pk.to_bytes(),
    };

    let state = ClientHandshakeState {
        client_hello: client_hello.clone(),
        kyber_sk,
        x25519_sk,
        x25519_pk,
    };

    (client_hello, state)
}

pub fn handle_client_hello(
    client_hello: ClientHello,
) -> Result<(ServerHello, Session), HandshakeError> {
    if client_hello.version != PROTOCOL_VERSION {
        return Err(HandshakeError::InvalidVersion);
    }
    if client_hello.kyber_pk.len() != KYBER768_PK_SIZE {
        return Err(HandshakeError::InvalidKeySize);
    }

    let client_kyber_pk =
        pqcrypto_kyber::kyber768::PublicKey::from_bytes(&client_hello.kyber_pk)
            .map_err(|_| HandshakeError::InvalidKeySize)?;
    let client_x25519_pk = x25519_dalek::PublicKey::from(client_hello.x25519_pk);

    let (server_x25519_pk, server_x25519_sk) = X25519Kem::generate_keypair();

    let (kyber_ct, ss_pq) = Kyber768Kem::encapsulate(&client_kyber_pk);

    let dh = server_x25519_sk.diffie_hellman(&client_x25519_pk);
    let ss_classical = dh.as_bytes().to_vec();

    let server_hello = ServerHello {
        kyber_ct: kyber_ct.as_bytes().to_vec(),
        x25519_pk: server_x25519_pk.to_bytes(),
    };

    let transcript = compute_transcript(&client_hello, &server_hello);
    let keys = derive_session_keys(&ss_pq, &ss_classical, &transcript);

    Ok((
        server_hello,
        Session {
            keys,
            transcript,
            is_client: false,
        },
    ))
}

pub fn handle_server_hello(
    server_hello: ServerHello,
    state: ClientHandshakeState,
) -> Result<Session, HandshakeError> {
    if server_hello.kyber_ct.len() != KYBER768_CT_SIZE {
        return Err(HandshakeError::InvalidKeySize);
    }

    let kyber_ct =
        pqcrypto_kyber::kyber768::Ciphertext::from_bytes(&server_hello.kyber_ct)
            .map_err(|_| HandshakeError::InvalidKeySize)?;

    let ss_pq = Kyber768Kem::decapsulate(&state.kyber_sk, &kyber_ct);

    let server_x25519_pk = x25519_dalek::PublicKey::from(server_hello.x25519_pk);
    let dh = state.x25519_sk.diffie_hellman(&server_x25519_pk);
    let ss_classical = dh.as_bytes().to_vec();

    let transcript = compute_transcript(&state.client_hello, &server_hello);
    let keys = derive_session_keys(&ss_pq, &ss_classical, &transcript);

    Ok(Session {
        keys,
        transcript,
        is_client: true,
    })
}
