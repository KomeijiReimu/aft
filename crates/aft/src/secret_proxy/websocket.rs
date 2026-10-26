use std::sync::Arc;

use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

use super::State;

pub(super) async fn relay(
    client: hyper::upgrade::Upgraded,
    upstream: hyper::upgrade::Upgraded,
    state: Arc<State>,
) {
    let (mut client_read, mut client_write) = tokio::io::split(TokioIo::new(client));
    let (mut upstream_read, mut upstream_write) = tokio::io::split(TokioIo::new(upstream));
    // Client frames are never substituted. In particular, a placeholder in a
    // data frame is not a second handshake credential location.
    tokio::select! {
        _ = tokio::io::copy(&mut client_read, &mut upstream_write) => {},
        _ = server_frames(&mut upstream_read, &mut client_write, &state) => {},
    }
}

async fn server_frames<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut R,
    writer: &mut W,
    state: &State,
) -> Result<(), ()> {
    let mut message = Zeroizing::new(Vec::new());
    let mut opcode = None;
    loop {
        let mut header = [0u8; 2];
        reader.read_exact(&mut header).await.map_err(|_| ())?;
        // Reject reserved bits before reading or forwarding the frame payload.
        if header[0] & 0x70 != 0 || header[1] & 0x80 != 0 {
            return Err(());
        }
        let fin = header[0] & 0x80 != 0;
        let kind = header[0] & 0x0f;
        let length = match header[1] & 0x7f {
            126 => reader.read_u16().await.map_err(|_| ())? as u64,
            127 => reader.read_u64().await.map_err(|_| ())?,
            size => size as u64,
        };
        // Cap each accumulated message at 16 MiB so a fragmented message
        // cannot grow without limit.
        if length > 16 * 1024 * 1024 || message.len() as u64 + length > 16 * 1024 * 1024 {
            return Err(());
        }
        let mut payload = Zeroizing::new(vec![0u8; length as usize]);
        reader.read_exact(&mut payload).await.map_err(|_| ())?;
        match kind {
            0x8..=0xa => {
                if !fin || length > 125 {
                    return Err(());
                }
                let clean = state.scrub(&payload)?;
                if clean.len() > 125 {
                    return Err(());
                }
                write_frame(writer, kind, &clean).await?;
                if kind == 8 {
                    return Ok(());
                }
            }
            1 | 2 if opcode.is_none() => {
                opcode = Some(kind);
                message.extend_from_slice(&payload);
            }
            0 if opcode.is_some() => message.extend_from_slice(&payload),
            _ => return Err(()),
        }
        if kind < 8 && fin {
            let clean = state.scrub(&message)?;
            write_frame(writer, opcode.take().ok_or(())?, &clean).await?;
            message.clear();
        }
    }
}

async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    opcode: u8,
    payload: &[u8],
) -> Result<(), ()> {
    writer.write_u8(0x80 | opcode).await.map_err(|_| ())?;
    match payload.len() {
        0..=125 => writer.write_u8(payload.len() as u8).await.map_err(|_| ())?,
        126..=65535 => {
            writer.write_u8(126).await.map_err(|_| ())?;
            writer
                .write_u16(payload.len() as u16)
                .await
                .map_err(|_| ())?;
        }
        _ => {
            writer.write_u8(127).await.map_err(|_| ())?;
            writer
                .write_u64(payload.len() as u64)
                .await
                .map_err(|_| ())?;
        }
    }
    writer.write_all(payload).await.map_err(|_| ())?;
    writer.flush().await.map_err(|_| ())
}
