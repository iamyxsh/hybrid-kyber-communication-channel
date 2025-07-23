use tokio::net::TcpListener;

use protocol::framing::{read_frame, write_frame};
use protocol::handshake::handle_client_hello;
use protocol::messages::{AppData, ClientHello};
use protocol::session::SecureChannel;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:8080").await?;
    println!("Server listening on 127.0.0.1:8080");

    loop {
        let (socket, addr) = listener.accept().await?;
        println!("Client connected from {}", addr);

        tokio::spawn(async move {
            if let Err(e) = handle_connection(socket).await {
                eprintln!("Connection error: {:?}", e);
            }
        });
    }
}

async fn handle_connection(
    socket: tokio::net::TcpStream,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (mut reader, mut writer) = socket.into_split();

    // --- Handshake ---
    let client_hello_bytes = read_frame(&mut reader).await?;
    let client_hello =
        ClientHello::from_bytes(&client_hello_bytes).map_err(|_| "Invalid ClientHello")?;

    let (server_hello, session) =
        handle_client_hello(client_hello).map_err(|e| format!("Handshake failed: {:?}", e))?;

    write_frame(&mut writer, &server_hello.to_bytes()).await?;
    println!("Handshake complete!");

    let mut channel = SecureChannel::new(session.keys, session.transcript, false);

    // --- Message Loop ---
    loop {
        let frame = match read_frame(&mut reader).await {
            Ok(f) => f,
            Err(_) => {
                println!("Client disconnected");
                break;
            }
        };

        let app_data = AppData::from_bytes(&frame).map_err(|_| "Invalid AppData")?;

        let plaintext = channel
            .decrypt(&app_data)
            .map_err(|e| format!("Decryption failed: {:?}", e))?;

        let message = String::from_utf8_lossy(&plaintext);
        println!("[recv] {}", message);

        // Echo back with prefix
        let response = format!("Server received: {}", message);
        let encrypted = channel.encrypt(response.as_bytes());
        write_frame(&mut writer, &encrypted.to_bytes()).await?;
    }

    Ok(())
}
