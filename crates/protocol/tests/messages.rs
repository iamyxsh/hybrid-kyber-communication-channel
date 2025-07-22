use hybrid_kyber_protocol::messages::{AppData, ClientHello, ServerHello};

#[test]
fn test_client_hello_roundtrip() {
    let msg = ClientHello {
        version: 1,
        kyber_pk: vec![0xAA; 1184],
        x25519_pk: [0xBB; 32],
    };

    let bytes = msg.to_bytes();
    let recovered = ClientHello::from_bytes(&bytes).unwrap();

    assert_eq!(recovered.version, 1);
    assert_eq!(recovered.kyber_pk.len(), 1184);
    assert_eq!(recovered.x25519_pk, [0xBB; 32]);
}

#[test]
fn test_server_hello_roundtrip() {
    let msg = ServerHello {
        kyber_ct: vec![0xCC; 1088],
        x25519_pk: [0xDD; 32],
    };

    let bytes = msg.to_bytes();
    let recovered = ServerHello::from_bytes(&bytes).unwrap();

    assert_eq!(recovered.kyber_ct.len(), 1088);
    assert_eq!(recovered.x25519_pk, [0xDD; 32]);
}

#[test]
fn test_app_data_roundtrip() {
    let msg = AppData {
        seq: 42,
        ciphertext: vec![0xEE; 100],
    };

    let bytes = msg.to_bytes();
    let recovered = AppData::from_bytes(&bytes).unwrap();

    assert_eq!(recovered.seq, 42);
    assert_eq!(recovered.ciphertext.len(), 100);
}
