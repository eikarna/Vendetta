use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{self, Instant};

use crate::error::{Result, VendettaError};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RelayStats {
    pub left_to_right: u64,
    pub right_to_left: u64,
}

pub async fn copy_bidirectional<L, R>(
    left: L,
    right: R,
    buffer_size: usize,
) -> Result<RelayStats>
where
    L: AsyncRead + AsyncWrite + Unpin,
    R: AsyncRead + AsyncWrite + Unpin,
{
    copy_bidirectional_with_idle(left, right, buffer_size, None).await
}

pub async fn copy_bidirectional_with_idle<L, R>(
    mut left: L,
    mut right: R,
    buffer_size: usize,
    idle_timeout: Option<Duration>,
) -> Result<RelayStats>
where
    L: AsyncRead + AsyncWrite + Unpin,
    R: AsyncRead + AsyncWrite + Unpin,
{
    if buffer_size == 0 {
        return Err(VendettaError::Config(
            "relay buffer size must be greater than zero".to_string(),
        ));
    }

    match idle_timeout {
        Some(timeout) => {
            copy_loop_with_idle(&mut left, &mut right, buffer_size, timeout).await
        }
        None => copy_loop(&mut left, &mut right, buffer_size).await,
    }
}

async fn copy_loop<L, R>(left: &mut L, right: &mut R, buffer_size: usize) -> Result<RelayStats>
where
    L: AsyncRead + AsyncWrite + Unpin,
    R: AsyncRead + AsyncWrite + Unpin,
{
    let mut left_buffer = vec![0_u8; buffer_size];
    let mut right_buffer = vec![0_u8; buffer_size];
    let mut left_eof = false;
    let mut right_eof = false;
    let mut stats = RelayStats::default();

    while !left_eof || !right_eof {
        tokio::select! {
            result = left.read(&mut left_buffer), if !left_eof => {
                left_eof = relay_read_result(result?, &left_buffer, right, |bytes| {
                    stats.left_to_right += bytes;
                }).await?;
            }
            result = right.read(&mut right_buffer), if !right_eof => {
                right_eof = relay_read_result(result?, &right_buffer, left, |bytes| {
                    stats.right_to_left += bytes;
                }).await?;
            }
        }
    }

    Ok(stats)
}

async fn copy_loop_with_idle<L, R>(
    left: &mut L,
    right: &mut R,
    buffer_size: usize,
    idle_timeout: Duration,
) -> Result<RelayStats>
where
    L: AsyncRead + AsyncWrite + Unpin,
    R: AsyncRead + AsyncWrite + Unpin,
{
    let mut left_buffer = vec![0_u8; buffer_size];
    let mut right_buffer = vec![0_u8; buffer_size];
    let mut left_eof = false;
    let mut right_eof = false;
    let mut stats = RelayStats::default();
    let idle_sleep = time::sleep(idle_timeout);
    tokio::pin!(idle_sleep);

    while !left_eof || !right_eof {
        tokio::select! {
            result = left.read(&mut left_buffer), if !left_eof => {
                left_eof = relay_read_result(result?, &left_buffer, right, |bytes| {
                    stats.left_to_right += bytes;
                }).await?;
                idle_sleep.as_mut().reset(Instant::now() + idle_timeout);
            }
            result = right.read(&mut right_buffer), if !right_eof => {
                right_eof = relay_read_result(result?, &right_buffer, left, |bytes| {
                    stats.right_to_left += bytes;
                }).await?;
                idle_sleep.as_mut().reset(Instant::now() + idle_timeout);
            }
            _ = &mut idle_sleep => {
                return Err(VendettaError::Timeout("relaying idle TCP stream"));
            }
        }
    }

    Ok(stats)
}

async fn relay_read_result<W, F>(
    read_len: usize,
    buffer: &[u8],
    writer: &mut W,
    mut record_bytes: F,
) -> Result<bool>
where
    W: AsyncWrite + Unpin,
    F: FnMut(u64),
{
    if read_len == 0 {
        writer.shutdown().await?;
        return Ok(true);
    }

    writer.write_all(&buffer[..read_len]).await?;
    record_bytes(read_len as u64);
    Ok(false)
}
