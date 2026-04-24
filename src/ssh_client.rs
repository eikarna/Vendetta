use std::sync::Arc;

use russh::client;
use russh::keys::ssh_key::PublicKey;
use secrecy::ExposeSecret;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;

use crate::config::ClientConfig;
use crate::error::{Result, VendettaError};
use crate::tls;

pub type SshHandle = Arc<Mutex<client::Handle<TlsVerifiedNoHostKeyCheck>>>;

#[derive(Debug, Clone)]
pub struct TlsVerifiedNoHostKeyCheck;

impl client::Handler for TlsVerifiedNoHostKeyCheck {
    type Error = VendettaError;

    async fn check_server_key(&mut self, _server_public_key: &PublicKey) -> Result<bool> {
        Ok(true)
    }
}

pub async fn connect(config: &ClientConfig) -> Result<SshHandle> {
    let tls_stream = tls::connect(
        &config.server_addr,
        &config.server_name,
        config.connect_timeout(),
    )
    .await?;

    connect_over_stream(
        tls_stream,
        &config.username,
        config.password.expose_secret(),
    )
    .await
}

pub async fn connect_over_stream<S>(stream: S, username: &str, password: &str) -> Result<SshHandle>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let ssh_config = Arc::new(client::Config::default());
    let mut handle =
        client::connect_stream(ssh_config, stream, TlsVerifiedNoHostKeyCheck).await?;
    let auth_result = handle
        .authenticate_password(username.to_string(), password.to_string())
        .await?;

    if !auth_result.success() {
        return Err(VendettaError::AuthenticationFailed);
    }

    Ok(Arc::new(Mutex::new(handle)))
}
