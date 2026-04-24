use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use rand_core::OsRng;
use secrecy::SecretString;
use serde::Deserialize;

use crate::error::{Result, VendettaError};

#[derive(Clone, Deserialize)]
pub struct ClientConfig {
    pub local_bind: String,
    pub server_addr: String,
    pub server_name: String,
    pub username: String,
    pub password: SecretString,
    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    #[serde(default = "default_idle_timeout_secs")]
    pub idle_timeout_secs: u64,
    #[serde(default = "default_relay_buffer_bytes")]
    pub relay_buffer_bytes: usize,
}

impl fmt::Debug for ClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientConfig")
            .field("local_bind", &self.local_bind)
            .field("server_addr", &self.server_addr)
            .field("server_name", &self.server_name)
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("connect_timeout_ms", &self.connect_timeout_ms)
            .field("idle_timeout_secs", &self.idle_timeout_secs)
            .field("relay_buffer_bytes", &self.relay_buffer_bytes)
            .finish()
    }
}

impl ClientConfig {
    pub fn connect_timeout(&self) -> Duration {
        Duration::from_millis(self.connect_timeout_ms)
    }

    pub fn idle_timeout(&self) -> Option<Duration> {
        if self.idle_timeout_secs == 0 {
            None
        } else {
            Some(Duration::from_secs(self.idle_timeout_secs))
        }
    }

    fn validate(&self) -> Result<()> {
        if self.relay_buffer_bytes == 0 {
            return Err(VendettaError::Config(
                "relay_buffer_bytes must be greater than zero".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct ServerConfig {
    pub listen: String,
    pub tls_cert_path: PathBuf,
    pub tls_key_path: PathBuf,
    pub ssh_host_key_path: PathBuf,
    pub users: Vec<UserConfig>,
    #[serde(default = "default_max_channels_per_session")]
    pub max_channels_per_session: usize,
    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    #[serde(default = "default_relay_buffer_bytes")]
    pub relay_buffer_bytes: usize,
}

impl ServerConfig {
    pub fn connect_timeout(&self) -> Duration {
        Duration::from_millis(self.connect_timeout_ms)
    }

    pub fn user_hashes(&self) -> HashMap<String, String> {
        self.users
            .iter()
            .map(|user| (user.username.clone(), user.password_hash.clone()))
            .collect()
    }

    fn validate(&self) -> Result<()> {
        if self.users.is_empty() {
            return Err(VendettaError::Config(
                "server config must contain at least one user".to_string(),
            ));
        }
        if self.max_channels_per_session == 0 {
            return Err(VendettaError::Config(
                "max_channels_per_session must be greater than zero".to_string(),
            ));
        }
        if self.relay_buffer_bytes == 0 {
            return Err(VendettaError::Config(
                "relay_buffer_bytes must be greater than zero".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct UserConfig {
    pub username: String,
    pub password_hash: String,
}

pub fn read_client_config(path: impl AsRef<Path>) -> Result<ClientConfig> {
    let config: ClientConfig = read_json(path)?;
    config.validate()?;
    Ok(config)
}

pub fn read_server_config(path: impl AsRef<Path>) -> Result<ServerConfig> {
    let config: ServerConfig = read_json(path)?;
    config.validate()?;
    Ok(config)
}

pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = argon2id()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|error| VendettaError::PasswordHash(error.to_string()))?;
    Ok(hash.to_string())
}

pub fn verify_password_hash(password_hash: &str, password: &str) -> Result<bool> {
    let parsed_hash = PasswordHash::new(password_hash)
        .map_err(|error| VendettaError::PasswordHash(error.to_string()))?;
    Ok(argon2id()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}

fn read_json<T: for<'de> Deserialize<'de>>(path: impl AsRef<Path>) -> Result<T> {
    let data = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&data)?)
}

fn argon2id() -> Argon2<'static> {
    Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::default())
}

fn default_connect_timeout_ms() -> u64 {
    10_000
}

fn default_idle_timeout_secs() -> u64 {
    300
}

fn default_relay_buffer_bytes() -> usize {
    16 * 1024
}

fn default_max_channels_per_session() -> usize {
    128
}

#[cfg(test)]
mod tests {
    use super::{hash_password, verify_password_hash};

    #[test]
    fn password_hash_verifies_success_and_failure() {
        let hash = hash_password("correct horse battery staple").expect("hash password");

        assert!(verify_password_hash(&hash, "correct horse battery staple").expect("verify hash"));
        assert!(!verify_password_hash(&hash, "wrong password").expect("verify hash"));
    }
}
