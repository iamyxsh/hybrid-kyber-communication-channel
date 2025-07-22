use hybrid_kyber_protocol::handshake::{generate_client_hello, handle_client_hello, handle_server_hello};
use hybrid_kyber_protocol::session::{ChannelError, SecureChannel};

fn create_channel_pair() -> (SecureChannel, SecureChannel) {
    let (client_hello, client_state) = generate_client_hello();
    let (server_hello, server_session) = handle_client_hello(client_hello).unwrap();
    let client_session = handle_server_hello(server_hello, client_state).unwrap();

    let client_channel = SecureChannel::new(
        client_session.keys,
        client_session.transcript,
        true,
    );
    let server_channel = SecureChannel::new(
        server_session.keys,
        server_session.transcript,
        false,
    );

    (client_channel, server_channel)
}

#[test]
fn test_client_to_server() {
    let (mut client, mut server) = create_channel_pair();

    let plaintext = b"hello server!";
    let encrypted = client.encrypt(plaintext);
    let decrypted = server.decrypt(&encrypted).unwrap();

    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_server_to_client() {
    let (mut client, mut server) = create_channel_pair();

    let plaintext = b"hello client!";
    let encrypted = server.encrypt(plaintext);
    let decrypted = client.decrypt(&encrypted).unwrap();

    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_replay_rejected() {
    let (mut client, mut server) = create_channel_pair();

    let encrypted = client.encrypt(b"message 1");
    server.decrypt(&encrypted).unwrap();

    let result = server.decrypt(&encrypted);
    assert!(matches!(result, Err(ChannelError::ReplayDetected)));
}

#[test]
fn test_out_of_order_rejected() {
    let (mut client, mut server) = create_channel_pair();

    let msg1 = client.encrypt(b"message 1");
    let msg2 = client.encrypt(b"message 2");

    server.decrypt(&msg2).unwrap();

    let result = server.decrypt(&msg1);
    assert!(matches!(result, Err(ChannelError::ReplayDetected)));
}
