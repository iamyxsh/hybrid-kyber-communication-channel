use tokio::io::{self, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use protocol::framing::{read_frame, write_frame};
use protocol::handshake::{generate_client_hello, handle_server_hello};
use protocol::messages::{AppData, ServerHello};
use protocol::session::SecureChannel;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let socket = TcpStream::connect("127.0.0.1:8080").await?;
    println!("Connected to server");

    let (mut reader, mut writer) = socket.into_split();

    // --- Handshake ---
    let (client_hello, state) = generate_client_hello();
    write_frame(&mut writer, &client_hello.to_bytes()).await?;

    let server_hello_bytes = read_frame(&mut reader).await?;
    let server_hello =
        ServerHello::from_bytes(&server_hello_bytes).map_err(|_| "Invalid ServerHello")?;

    let session = handle_server_hello(server_hello, state)
        .map_err(|e| format!("Handshake failed: {:?}", e))?;

    println!("Handshake complete! Quantum-resistant channel established.\n");

    let mut channel = SecureChannel::new(session.keys, session.transcript, true);

    // --- Message Loop (request-response) ---
    let stdin = BufReader::new(io::stdin());
    let mut lines = stdin.lines();

    println!("Type a message and press Enter (Ctrl+C to quit):");

    loop {
        print!("> ");
        io::stdout().flush().await?;

        let line = match lines.next_line().await? {
            Some(l) => l,
            None => break,
        };

        if line.is_empty() {
            continue;
        }

        // Encrypt and send
        let encrypted = channel.encrypt(line.as_bytes());
        write_frame(&mut writer, &encrypted.to_bytes()).await?;

        // Read response
        let response_frame = read_frame(&mut reader).await?;
        let response_data =
            AppData::from_bytes(&response_frame).map_err(|_| "Invalid AppData")?;

        let plaintext = channel
            .decrypt(&response_data)
            .map_err(|e| format!("Decryption failed: {:?}", e))?;

        let message = String::from_utf8_lossy(&plaintext);
        println!("[server] {}", message);
    }

    Ok(())
}
