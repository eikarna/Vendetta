use std::error::Error;
use std::fs;
use std::io::BufReader;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::{ClientConfig as RustlsClientConfig, RootCertStore};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time;
use vendetta::config::{hash_password, ServerConfig, UserConfig};
use vendetta::egress::EgressPolicy;
use vendetta::{socks, ssh_client, ssh_server, tls};

type TestResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

const TEST_SSH_HOST_KEY: &str = r#"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCN8JJ2PKnpuAFpjxcSBshc9p6nPmSWY9nhtvvZmzTibwAAAJg5D6LWOQ+i
1gAAAAtzc2gtZWQyNTUxOQAAACCN8JJ2PKnpuAFpjxcSBshc9p6nPmSWY9nhtvvZmzTibw
AAAEBj5bsdtweMm1GaYrBoyOvhZKCuHxs7/q75XXENpAjKgI3wknY8qem4AWmPFxIGyFz2
nqc+ZJZj2eG2+9mbNOJvAAAADnJvb3RAbG9jYWxob3N0AQIDBAUGBw==
-----END OPENSSH PRIVATE KEY-----
"#;

#[tokio::test]
async fn socks_connect_reaches_echo_through_tls_ssh() -> TestResult<()> {
    let temp_dir = tempfile::tempdir()?;
    let (server_config, tls_client_config) = make_server_config(&temp_dir)?;

    let echo_listener = TcpListener::bind("127.0.0.1:0").await?;
    let echo_addr = echo_listener.local_addr()?;
    let echo_task = tokio::spawn(async move {
        let (mut socket, _) = echo_listener.accept().await?;
        let mut buffer = [0_u8; 1024];
        let read_len = socket.read(&mut buffer).await?;
        socket.write_all(&buffer[..read_len]).await?;
        socket.read(&mut buffer).await
    });

    let server_listener = TcpListener::bind("127.0.0.1:0").await?;
    let server_addr = server_listener.local_addr()?;
    let server_task = tokio::spawn(async move {
        ssh_server::run_with_listener(
            server_listener,
            server_config,
            EgressPolicy::AllowAllForTests,
        )
        .await
    });

    let tls_stream = tls::connect_with_config(
        &server_addr.to_string(),
        "localhost",
        tls_client_config,
        Duration::from_secs(5),
    )
    .await?;
    let ssh_handle =
        ssh_client::connect_over_stream(tls_stream, "alice", "wonderland").await?;

    let socks_listener = TcpListener::bind("127.0.0.1:0").await?;
    let socks_addr = socks_listener.local_addr()?;
    let socks_task = tokio::spawn(async move {
        socks::serve(
            socks_listener,
            ssh_handle,
            4096,
            Some(Duration::from_secs(10)),
        )
        .await
    });

    let mut client = TcpStream::connect(socks_addr).await?;
    client.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut greeting_reply = [0_u8; 2];
    client.read_exact(&mut greeting_reply).await?;
    assert_eq!(greeting_reply, [0x05, 0x00]);

    let IpAddr::V4(target_ip) = echo_addr.ip() else {
        return Err("test echo listener did not bind IPv4".into());
    };
    let mut connect_request = vec![0x05, 0x01, 0x00, 0x01];
    connect_request.extend_from_slice(&target_ip.octets());
    connect_request.extend_from_slice(&echo_addr.port().to_be_bytes());
    client.write_all(&connect_request).await?;

    let mut connect_reply = [0_u8; 10];
    client.read_exact(&mut connect_reply).await?;
    assert_eq!(connect_reply[1], 0x00);

    client.write_all(b"vendetta").await?;
    let mut echoed = [0_u8; 8];
    client.read_exact(&mut echoed).await?;
    assert_eq!(&echoed, b"vendetta");

    drop(client);
    let echo_eof = time::timeout(Duration::from_secs(5), echo_task).await???;
    assert_eq!(echo_eof, 0);

    socks_task.abort();
    server_task.abort();
    Ok(())
}

fn make_server_config(temp_dir: &TempDir) -> TestResult<(ServerConfig, Arc<RustlsClientConfig>)> {
    let certified_key = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    let cert_pem = certified_key.cert.pem();
    let key_pem = certified_key.signing_key.serialize_pem();

    let cert_path = temp_dir.path().join("cert.pem");
    let key_path = temp_dir.path().join("key.pem");
    let ssh_key_path = temp_dir.path().join("ssh_host_key");
    fs::write(&cert_path, &cert_pem)?;
    fs::write(&key_path, key_pem)?;
    fs::write(&ssh_key_path, TEST_SSH_HOST_KEY)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&ssh_key_path, fs::Permissions::from_mode(0o600))?;
    }

    let mut roots = RootCertStore::empty();
    let certs: Result<Vec<_>, _> =
        rustls_pemfile::certs(&mut BufReader::new(cert_pem.as_bytes())).collect();
    for cert in certs? {
        roots.add(cert)?;
    }
    let tls_client_config = Arc::new(
        RustlsClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );

    Ok((
        ServerConfig {
            listen: "127.0.0.1:0".to_string(),
            tls_cert_path: cert_path,
            tls_key_path: key_path,
            ssh_host_key_path: ssh_key_path,
            users: vec![UserConfig {
                username: "alice".to_string(),
                password_hash: hash_password("wonderland")?,
            }],
            max_channels_per_session: 16,
            connect_timeout_ms: 5_000,
            relay_buffer_bytes: 4096,
        },
        tls_client_config,
    ))
}
