use std::io::Read;
use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing::info;
use tracing_subscriber::EnvFilter;
use vendetta::{config, socks, ssh_client, ssh_server};

#[derive(Debug, Parser)]
#[command(name = "vendetta")]
#[command(about = "Encrypted SOCKS5 TCP proxy over TLS plus SSH direct-tcpip")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Client {
        #[arg(long)]
        config: PathBuf,
    },
    Server {
        #[arg(long)]
        config: PathBuf,
    },
    HashPassword {
        #[arg(long)]
        password_stdin: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing()?;
    let cli = Cli::parse();

    match cli.command {
        Command::Client { config } => {
            let config = config::read_client_config(config)?;
            run_client(config).await?;
        }
        Command::Server { config } => {
            let config = config::read_server_config(config)?;
            ssh_server::run(config).await?;
        }
        Command::HashPassword { password_stdin } => {
            if !password_stdin {
                anyhow::bail!("hash-password requires --password-stdin");
            }

            let mut password = String::new();
            std::io::stdin().read_to_string(&mut password)?;
            let password = password.trim_end_matches(['\r', '\n']);
            println!("{}", config::hash_password(password)?);
        }
    }

    Ok(())
}

async fn run_client(config: config::ClientConfig) -> Result<()> {
    let ssh_handle = ssh_client::connect(&config).await?;
    info!(local_bind = %config.local_bind, "SOCKS5 client listening");
    socks::run(
        &config.local_bind,
        ssh_handle,
        config.relay_buffer_bytes,
        config.idle_timeout(),
    )
    .await?;
    Ok(())
}

fn init_tracing() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
        .init();
    Ok(())
}
