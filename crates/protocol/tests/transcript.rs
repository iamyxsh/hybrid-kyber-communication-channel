use hybrid_kyber_protocol::messages::{ClientHello, ServerHello};
use hybrid_kyber_protocol::transcript::compute_transcript;

#[test]
fn test_transcript_deterministic() {
    let ch = ClientHello {
        version: 1,
        kyber_pk: vec![0xAA; 1184],
        x25519_pk: [0xBB; 32],
    };
    let sh = ServerHello {
        kyber_ct: vec![0xCC; 1088],
        x25519_pk: [0xDD; 32],
    };

    let t1 = compute_transcript(&ch, &sh);
    let t2 = compute_transcript(&ch, &sh);

    assert_eq!(t1, t2);
}

#[test]
fn test_transcript_changes_with_input() {
    let ch = ClientHello {
        version: 1,
        kyber_pk: vec![0xAA; 1184],
        x25519_pk: [0xBB; 32],
    };
    let sh1 = ServerHello {
        kyber_ct: vec![0xCC; 1088],
        x25519_pk: [0xDD; 32],
    };
    let sh2 = ServerHello {
        kyber_ct: vec![0xCC; 1088],
        x25519_pk: [0xEE; 32],
    };

    let t1 = compute_transcript(&ch, &sh1);
    let t2 = compute_transcript(&ch, &sh2);

    assert_ne!(t1, t2);
}
