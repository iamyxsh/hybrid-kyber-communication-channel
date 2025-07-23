use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Debug)]
pub enum FrameError {
    Io(std::io::Error),
    TooLarge,
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::Io(e) => write!(f, "IO error: {}", e),
            FrameError::TooLarge => write!(f, "Frame too large"),
        }
    }
}

impl std::error::Error for FrameError {}

impl From<std::io::Error> for FrameError {
    fn from(e: std::io::Error) -> Self {
        FrameError::Io(e)
    }
}

const MAX_FRAME_SIZE: u32 = 1024 * 1024; // 1MB max

/// Write a length-prefixed frame
pub async fn write_frame<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    data: &[u8],
) -> Result<(), FrameError> {
    let len = data.len() as u32;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(data).await?;
    writer.flush().await?;
    Ok(())
}

/// Read a length-prefixed frame
pub async fn read_frame<R: AsyncReadExt + Unpin>(
    reader: &mut R,
) -> Result<Vec<u8>, FrameError> {
    let mut len_bytes = [0u8; 4];
    reader.read_exact(&mut len_bytes).await?;
    let len = u32::from_be_bytes(len_bytes);

    if len > MAX_FRAME_SIZE {
        return Err(FrameError::TooLarge);
    }

    let mut data = vec![0u8; len as usize];
    reader.read_exact(&mut data).await?;
    Ok(data)
}
