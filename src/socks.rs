use std::convert::TryInto;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use bytes::{Buf, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, warn};

use crate::error::{Result, SocksError, VendettaError};
use crate::relay;
use crate::ssh_client::SshHandle;

const SOCKS_VERSION: u8 = 0x05;
const NO_AUTH: u8 = 0x00;
const NO_ACCEPTABLE_METHODS: u8 = 0xff;
const CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectRequest {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Reply {
    Succeeded = 0x00,
    GeneralFailure = 0x01,
    CommandNotSupported = 0x07,
    AddressTypeNotSupported = 0x08,
}

pub async fn run(
    bind_addr: &str,
    ssh_handle: SshHandle,
    relay_buffer_bytes: usize,
    idle_timeout: Option<Duration>,
) -> Result<()> {
    let listener = TcpListener::bind(bind_addr).await?;
    serve(listener, ssh_handle, relay_buffer_bytes, idle_timeout).await
}

pub async fn serve(
    listener: TcpListener,
    ssh_handle: SshHandle,
    relay_buffer_bytes: usize,
    idle_timeout: Option<Duration>,
) -> Result<()> {
    loop {
        let (client, peer_addr) = listener.accept().await?;
        let ssh_handle = ssh_handle.clone();

        tokio::spawn(async move {
            if let Err(error) =
                handle_client(client, ssh_handle, relay_buffer_bytes, idle_timeout).await
            {
                debug!(%peer_addr, %error, "SOCKS5 client disconnected with error");
            }
        });
    }
}

pub async fn negotiate_no_auth<S>(stream: &mut S) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut header = [0_u8; 2];
    stream.read_exact(&mut header).await?;
    let version = header[0];
    let method_count = header[1] as usize;

    if version != SOCKS_VERSION {
        return Err(SocksError::UnsupportedVersion(version).into());
    }

    let methods = read_exact_bytes(stream, method_count).await?;
    if !methods.contains(&NO_AUTH) {
        stream
            .write_all(&[SOCKS_VERSION, NO_ACCEPTABLE_METHODS])
            .await?;
        return Err(SocksError::UnsupportedMethod.into());
    }

    stream.write_all(&[SOCKS_VERSION, NO_AUTH]).await?;
    Ok(())
}

pub async fn read_connect_request<S>(stream: &mut S) -> Result<ConnectRequest>
where
    S: AsyncRead + Unpin,
{
    let mut frame = read_exact_bytes(stream, 4).await?;
    let address_type = *frame
        .get(3)
        .ok_or(SocksError::Truncated("address type"))?;

    match address_type {
        ATYP_IPV4 => frame.extend_from_slice(&read_exact_bytes(stream, 6).await?),
        ATYP_DOMAIN => {
            let length = read_exact_bytes(stream, 1).await?;
            let domain_len = *length.first().ok_or(SocksError::Truncated("domain length"))?;
            frame.extend_from_slice(&length);
            frame.extend_from_slice(&read_exact_bytes(stream, usize::from(domain_len) + 2).await?);
        }
        ATYP_IPV6 => frame.extend_from_slice(&read_exact_bytes(stream, 18).await?),
        other => return Err(SocksError::UnsupportedAddressType(other).into()),
    }

    parse_connect_request_frame(&frame).map_err(VendettaError::from)
}

pub fn parse_connect_request_frame(frame: &[u8]) -> std::result::Result<ConnectRequest, SocksError> {
    let mut buffer = BytesMut::from(frame);
    let version = take_u8(&mut buffer, "version")?;
    if version != SOCKS_VERSION {
        return Err(SocksError::UnsupportedVersion(version));
    }

    let command = take_u8(&mut buffer, "command")?;
    if command != CONNECT {
        return Err(SocksError::UnsupportedCommand(command));
    }

    let reserved = take_u8(&mut buffer, "reserved byte")?;
    if reserved != 0 {
        return Err(SocksError::InvalidReserved(reserved));
    }

    let address_type = take_u8(&mut buffer, "address type")?;
    let host = match address_type {
        ATYP_IPV4 => {
            let octets: [u8; 4] = take_bytes(&mut buffer, 4, "IPv4 address")?
                .as_ref()
                .try_into()
                .map_err(|_| SocksError::Truncated("IPv4 address"))?;
            Ipv4Addr::from(octets).to_string()
        }
        ATYP_DOMAIN => {
            // Domain addresses carry a one-byte length before the raw name. Check
            // it before split_to so malformed frames cannot trigger unbounded reads.
            let domain_len = usize::from(take_u8(&mut buffer, "domain length")?);
            if domain_len == 0 {
                return Err(SocksError::EmptyDomain);
            }
            let domain = take_bytes(&mut buffer, domain_len, "domain")?;
            String::from_utf8(domain.to_vec()).map_err(|_| SocksError::InvalidDomain)?
        }
        ATYP_IPV6 => {
            let octets: [u8; 16] = take_bytes(&mut buffer, 16, "IPv6 address")?
                .as_ref()
                .try_into()
                .map_err(|_| SocksError::Truncated("IPv6 address"))?;
            Ipv6Addr::from(octets).to_string()
        }
        other => return Err(SocksError::UnsupportedAddressType(other)),
    };

    // The SOCKS5 port field is network byte order, i.e. big-endian.
    let port_bytes: [u8; 2] = take_bytes(&mut buffer, 2, "port")?
        .as_ref()
        .try_into()
        .map_err(|_| SocksError::Truncated("port"))?;
    let port = u16::from_be_bytes(port_bytes);

    if !buffer.is_empty() {
        return Err(SocksError::Truncated("unexpected trailing bytes"));
    }

    Ok(ConnectRequest { host, port })
}

pub async fn write_reply<S>(stream: &mut S, reply: Reply) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    stream
        .write_all(&[SOCKS_VERSION, reply as u8, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
        .await?;
    Ok(())
}

async fn handle_client(
    mut client: TcpStream,
    ssh_handle: SshHandle,
    relay_buffer_bytes: usize,
    idle_timeout: Option<Duration>,
) -> Result<()> {
    negotiate_no_auth(&mut client).await?;

    let request = match read_connect_request(&mut client).await {
        Ok(request) => request,
        Err(error) => {
            let reply = match &error {
                VendettaError::Socks(SocksError::UnsupportedCommand(_)) => {
                    Reply::CommandNotSupported
                }
                VendettaError::Socks(SocksError::UnsupportedAddressType(_)) => {
                    Reply::AddressTypeNotSupported
                }
                _ => Reply::GeneralFailure,
            };
            write_reply(&mut client, reply).await?;
            return Err(error);
        }
    };

    let channel = match ssh_handle
        .lock()
        .await
        .channel_open_direct_tcpip(request.host.clone(), u32::from(request.port), "0.0.0.0", 0)
        .await
    {
        Ok(channel) => channel,
        Err(error) => {
            warn!(target_host = %request.host, target_port = request.port, %error, "SSH direct-tcpip open failed");
            write_reply(&mut client, Reply::GeneralFailure).await?;
            return Err(error.into());
        }
    };

    write_reply(&mut client, Reply::Succeeded).await?;
    relay::copy_bidirectional_with_idle(
        client,
        channel.into_stream(),
        relay_buffer_bytes,
        idle_timeout,
    )
    .await?;
    Ok(())
}

async fn read_exact_bytes<S>(stream: &mut S, len: usize) -> Result<BytesMut>
where
    S: AsyncRead + Unpin,
{
    let mut buffer = BytesMut::with_capacity(len);
    buffer.resize(len, 0);
    stream.read_exact(&mut buffer).await?;
    Ok(buffer)
}

fn take_u8(buffer: &mut BytesMut, context: &'static str) -> std::result::Result<u8, SocksError> {
    let value = *buffer.first().ok_or(SocksError::Truncated(context))?;
    buffer.advance(1);
    Ok(value)
}

fn take_bytes(
    buffer: &mut BytesMut,
    len: usize,
    context: &'static str,
) -> std::result::Result<BytesMut, SocksError> {
    if buffer.len() < len {
        return Err(SocksError::Truncated(context));
    }
    // split_to advances the BytesMut cursor while keeping the slice bounded by
    // the explicit length checks above.
    Ok(buffer.split_to(len))
}

#[cfg(test)]
mod tests {
    use super::parse_connect_request_frame;
    use crate::error::SocksError;

    #[test]
    fn parses_ipv4_connect_request() {
        let request = parse_connect_request_frame(&[
            0x05, 0x01, 0x00, 0x01, 192, 0, 2, 10, 0x01, 0xbb,
        ])
        .expect("parse IPv4 request");

        assert_eq!(request.host, "192.0.2.10");
        assert_eq!(request.port, 443);
    }

    #[test]
    fn parses_ipv6_connect_request() {
        let request = parse_connect_request_frame(&[
            0x05, 0x01, 0x00, 0x04, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            1, 0x1f, 0x90,
        ])
        .expect("parse IPv6 request");

        assert_eq!(request.host, "2001:db8::1");
        assert_eq!(request.port, 8080);
    }

    #[test]
    fn parses_domain_connect_request() {
        let request = parse_connect_request_frame(&[
            0x05, 0x01, 0x00, 0x03, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c',
            b'o', b'm', 0x00, 0x50,
        ])
        .expect("parse domain request");

        assert_eq!(request.host, "example.com");
        assert_eq!(request.port, 80);
    }

    #[test]
    fn rejects_malformed_version() {
        let error = parse_connect_request_frame(&[0x04, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 80])
            .expect_err("reject bad version");

        assert_eq!(error, SocksError::UnsupportedVersion(0x04));
    }

    #[test]
    fn rejects_unsupported_command() {
        let error = parse_connect_request_frame(&[0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0, 80])
            .expect_err("reject bind command");

        assert_eq!(error, SocksError::UnsupportedCommand(0x02));
    }

    #[test]
    fn rejects_invalid_address_type() {
        let error = parse_connect_request_frame(&[0x05, 0x01, 0x00, 0x09, 0, 80])
            .expect_err("reject address type");

        assert_eq!(error, SocksError::UnsupportedAddressType(0x09));
    }

    #[test]
    fn rejects_truncated_frames() {
        let error = parse_connect_request_frame(&[0x05, 0x01, 0x00, 0x01, 127])
            .expect_err("reject truncated IPv4");

        assert_eq!(error, SocksError::Truncated("IPv4 address"));
    }
}
