use hybrid_kyber_protocol::handshake::{generate_client_hello, handle_client_hello, handle_server_hello};

#[test]
fn test_full_handshake() {
    let (client_hello, client_state) = generate_client_hello();

    let (server_hello, server_session) = handle_client_hello(client_hello).unwrap();

    let client_session = handle_server_hello(server_hello, client_state).unwrap();

    assert_eq!(
        client_session.keys.k_client_to_server,
        server_session.keys.k_client_to_server
    );
    assert_eq!(
        client_session.keys.k_server_to_client,
        server_session.keys.k_server_to_client
    );
    assert_eq!(client_session.transcript, server_session.transcript);
}
