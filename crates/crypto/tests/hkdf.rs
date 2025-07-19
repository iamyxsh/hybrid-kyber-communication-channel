use hybrid_kyber_crypto::hkdf::derive_session_keys;

#[test]
fn test_derive_session_keys() {
    let ss_pq = vec![1u8; 32];
    let ss_classical = vec![2u8; 32];
    let transcript = [3u8; 32];

    let keys = derive_session_keys(&ss_pq, &ss_classical, &transcript);

    // Keys should be deterministic given same inputs
    let keys2 = derive_session_keys(&ss_pq, &ss_classical, &transcript);
    assert_eq!(keys.k_client_to_server, keys2.k_client_to_server);
    assert_eq!(keys.k_server_to_client, keys2.k_server_to_client);
    assert_eq!(keys.nonce_base_c2s, keys2.nonce_base_c2s);
    assert_eq!(keys.nonce_base_s2c, keys2.nonce_base_s2c);

    // Different inputs should produce different keys
    let different_transcript = [4u8; 32];
    let keys3 = derive_session_keys(&ss_pq, &ss_classical, &different_transcript);
    assert_ne!(keys.k_client_to_server, keys3.k_client_to_server);
}
