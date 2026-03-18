use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    pub node_name: Option<String>,
    pub network_name: String,
    pub node_port: u16,
    pub rpc_port: u16,
    pub public_port: u16,
    pub rpc_api_key: String,
    pub rpc_bind_localhost_only: bool,
    pub documents_dir: PathBuf,
    pub data_dir: PathBuf,
    pub secret_key_file: PathBuf,
    pub crypto_scheme: CryptoScheme,
    pub rate_limit: RateLimitConfig,
    pub genesis: Option<GenesisConfig>,
    pub bootstrap_peers: Vec<String>,
    pub expose_public_port: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CryptoScheme {
    #[serde(rename = "FROST")]
    Frost,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub max_new_files_per_day: u32,
    pub max_file_updates_per_day: u32,
    pub max_requests_per_day: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisConfig {
    pub member_name: String,
    pub public_key_hex: String,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            node_name: None,
            network_name: "quorum-trust-default".into(),
            node_port: 9400,
            rpc_port: 9401,
            public_port: 9402,
            rpc_api_key: uuid::Uuid::new_v4().to_string(),
            rpc_bind_localhost_only: true,
            documents_dir: PathBuf::from("./documents"),
            data_dir: PathBuf::from("./data"),
            secret_key_file: PathBuf::from("./data/secret.key"),
            crypto_scheme: CryptoScheme::Frost,
            rate_limit: RateLimitConfig::default(),
            genesis: None,
            bootstrap_peers: vec![],
            expose_public_port: true,
        }
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_new_files_per_day: 50,
            max_file_updates_per_day: 200,
            max_requests_per_day: 500,
        }
    }
}

impl NodeConfig {
    pub fn load_from_file(path: &std::path::Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: NodeConfig = toml::from_str(&content)?;
        Ok(config)
    }

    pub fn save_to_file(&self, path: &std::path::Path) -> anyhow::Result<()> {
        let content = toml::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }
}
