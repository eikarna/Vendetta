use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use russh::keys::load_secret_key;
use russh::{server, Channel};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time;
use tokio_rustls::server::TlsStream;
use tracing::{debug, info, warn};

use crate::config::{verify_password_hash, ServerConfig};
use crate::egress::{self, EgressPolicy};
use crate::error::{Result, VendettaError};
use crate::relay;
use crate::tls;

pub async fn run(config: ServerConfig) -> Result<()> {
    let listener = TcpListener::bind(&config.listen).await?;
    run_with_listener(listener, config, EgressPolicy::PublicInternet).await
}

#[doc(hidden)]
pub async fn run_with_listener(
    listener: TcpListener,
    config: ServerConfig,
    egress_policy: EgressPolicy,
) -> Result<()> {
    let local_addr = listener.local_addr()?;
    let tls_acceptor = tls::server_acceptor(&config)?;
    let ssh_config = Arc::new(build_ssh_config(&config)?);
    let state = Arc::new(ServerState::new(config, egress_policy));

    info!(%local_addr, "vendetta server listening");

    loop {
        let (tcp, peer_addr) = listener.accept().await?;
        let tls_acceptor = tls_acceptor.clone();
        let ssh_config = ssh_config.clone();
        let state = state.clone();

        tokio::spawn(async move {
            if let Err(error) = handle_connection(tcp, peer_addr, tls_acceptor, ssh_config, state).await
            {
                debug!(%peer_addr, %error, "server connection ended with error");
            }
        });
    }
}

fn build_ssh_config(config: &ServerConfig) -> Result<server::Config> {
    let mut ssh_config = server::Config::default();
    let mut methods = russh::MethodSet::empty();
    methods.push(russh::MethodKind::Password);
    ssh_config.methods = methods;
    ssh_config.nodelay = true;
    ssh_config.keys.push(
        load_secret_key(&config.ssh_host_key_path, None).map_err(|error| {
            VendettaError::Config(format!(
                "failed to load SSH host key {}: {error}",
                config.ssh_host_key_path.display()
            ))
        })?,
    );
    Ok(ssh_config)
}

async fn handle_connection(
    tcp: TcpStream,
    peer_addr: SocketAddr,
    tls_acceptor: tokio_rustls::TlsAcceptor,
    ssh_config: Arc<server::Config>,
    state: Arc<ServerState>,
) -> Result<()> {
    tcp.set_nodelay(true)?;
    let tls_stream = tls_acceptor
        .accept(tcp)
        .await
        .map_err(|error| VendettaError::Tls(error.to_string()))?;
    run_ssh_session(tls_stream, peer_addr, ssh_config, state).await
}

async fn run_ssh_session(
    tls_stream: TlsStream<TcpStream>,
    peer_addr: SocketAddr,
    ssh_config: Arc<server::Config>,
    state: Arc<ServerState>,
) -> Result<()> {
    let handler = ProxyHandler::new(state, peer_addr);
    let session = server::run_stream(ssh_config, tls_stream, handler).await?;
    session.await?;
    Ok(())
}

#[derive(Debug)]
struct ServerState {
    users: HashMap<String, String>,
    max_channels_per_session: usize,
    connect_timeout: std::time::Duration,
    relay_buffer_bytes: usize,
    egress_policy: EgressPolicy,
}

impl ServerState {
    fn new(config: ServerConfig, egress_policy: EgressPolicy) -> Self {
        Self {
            users: config.user_hashes(),
            max_channels_per_session: config.max_channels_per_session,
            connect_timeout: config.connect_timeout(),
            relay_buffer_bytes: config.relay_buffer_bytes,
            egress_policy,
        }
    }

    fn verify_user(&self, username: &str, password: &str) -> Result<bool> {
        let Some(password_hash) = self.users.get(username) else {
            return Ok(false);
        };

        verify_password_hash(password_hash, password)
    }
}

struct ProxyHandler {
    state: Arc<ServerState>,
    permits: Arc<Semaphore>,
    peer_addr: SocketAddr,
}

impl ProxyHandler {
    fn new(state: Arc<ServerState>, peer_addr: SocketAddr) -> Self {
        let permits = Arc::new(Semaphore::new(state.max_channels_per_session));
        Self {
            state,
            permits,
            peer_addr,
        }
    }
}

impl server::Handler for ProxyHandler {
    type Error = VendettaError;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<server::Auth> {
        match self.state.verify_user(user, password) {
            Ok(true) => {
                info!(%user, peer_addr = %self.peer_addr, "SSH password authentication accepted");
                Ok(server::Auth::Accept)
            }
            Ok(false) => Ok(server::Auth::reject()),
            Err(error) => {
                warn!(%user, %error, "password hash verification failed");
                Ok(server::Auth::reject())
            }
        }
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<server::Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        _session: &mut server::Session,
    ) -> Result<bool> {
        let Ok(port) = u16::try_from(port_to_connect) else {
            return Ok(false);
        };

        let permit = match self.permits.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                warn!(peer_addr = %self.peer_addr, "SSH session exceeded channel limit");
                return Ok(false);
            }
        };

        let resolved =
            match egress::resolve_target(host_to_connect, port, self.state.egress_policy).await {
                Ok(addresses) => addresses,
                Err(error) => {
                    warn!(%host_to_connect, port, %error, "egress policy rejected target");
                    return Ok(false);
                }
            };

        let outbound = match time::timeout(self.state.connect_timeout, connect_any(&resolved)).await
        {
            Ok(Ok(stream)) => stream,
            Ok(Err(error)) => {
                warn!(%host_to_connect, port, %error, "failed to connect to target");
                return Ok(false);
            }
            Err(_) => {
                warn!(%host_to_connect, port, "timed out connecting to target");
                return Ok(false);
            }
        };

        outbound.set_nodelay(true)?;
        let relay_buffer_bytes = self.state.relay_buffer_bytes;
        let channel_stream = channel.into_stream();
        let target = format!("{host_to_connect}:{port}");

        tokio::spawn(async move {
            let _permit = permit;
            if let Err(error) =
                relay::copy_bidirectional(channel_stream, outbound, relay_buffer_bytes).await
            {
                debug!(%target, %error, "direct-tcpip relay ended with error");
            }
        });

        Ok(true)
    }
}

async fn connect_any(addresses: &[SocketAddr]) -> std::io::Result<TcpStream> {
    let mut last_error = None;

    for address in addresses {
        match TcpStream::connect(address).await {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error),
        }
    }

    match last_error {
        Some(error) => Err(error),
        None => Err(std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            "no resolved addresses to connect",
        )),
    }
}
