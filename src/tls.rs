use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use rustls::{ClientConfig as RustlsClientConfig, ServerConfig as RustlsServerConfig};
use rustls_pki_types::ServerName;
use rustls_platform_verifier::ConfigVerifierExt;
use tokio::net::TcpStream;
use tokio::time;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::config::ServerConfig;
use crate::error::{Result, VendettaError};

pub async fn connect(
    addr: &str,
    server_name: &str,
    connect_timeout: Duration,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    connect_with_config(
        addr,
        server_name,
        platform_client_config()?,
        connect_timeout,
    )
    .await
}

pub async fn connect_with_config(
    addr: &str,
    server_name: &str,
    config: Arc<RustlsClientConfig>,
    connect_timeout: Duration,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let tcp = time::timeout(connect_timeout, TcpStream::connect(addr))
        .await
        .map_err(|_| VendettaError::Timeout("connecting TCP for TLS"))??;
    tcp.set_nodelay(true)?;

    let server_name = ServerName::try_from(server_name.to_string())
        .map_err(|error| VendettaError::Tls(error.to_string()))?;
    let connector = TlsConnector::from(config);

    time::timeout(connect_timeout, connector.connect(server_name, tcp))
        .await
        .map_err(|_| VendettaError::Timeout("performing TLS handshake"))?
        .map_err(VendettaError::from)
}

pub fn platform_client_config() -> Result<Arc<RustlsClientConfig>> {
    Ok(Arc::new(RustlsClientConfig::with_platform_verifier()?))
}

pub fn server_acceptor(config: &ServerConfig) -> Result<TlsAcceptor> {
    let certs = load_certs(&config.tls_cert_path)?;
    let key = load_private_key(&config.tls_key_path)?;
    let server_config = RustlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

fn load_certs(path: &Path) -> Result<Vec<rustls_pki_types::CertificateDer<'static>>> {
    let mut reader = BufReader::new(File::open(path)?);
    let certs: std::result::Result<Vec<_>, _> = rustls_pemfile::certs(&mut reader).collect();
    let certs = certs?;

    if certs.is_empty() {
        return Err(VendettaError::Tls(format!(
            "no certificates found in {}",
            path.display()
        )));
    }

    Ok(certs)
}

fn load_private_key(path: &Path) -> Result<rustls_pki_types::PrivateKeyDer<'static>> {
    let mut reader = BufReader::new(File::open(path)?);
    rustls_pemfile::private_key(&mut reader)?
        .ok_or_else(|| VendettaError::Tls(format!("no private key found in {}", path.display())))
}
