use crate::network::messages::{PeerInfo, GossipMessage, GossipMessageType};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::sync::RwLock;
use std::sync::Arc;

/// Persistent peer table - saves discovered peers to disk
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PeerTable {
    /// Map of address:port -> PeerInfo
    peers: HashMap<String, PeerInfo>,
}

impl PeerTable {
    /// Load peer table from disk
    pub fn load(data_dir: &PathBuf) -> anyhow::Result<Self> {
        let path = data_dir.join("peers.json");
        if path.exists() {
            let content = std::fs::read_to_string(&path)?;
            let table: PeerTable = serde_json::from_str(&content)?;
            tracing::info!("Loaded {} peers from disk", table.peers.len());
            Ok(table)
        } else {
            tracing::info!("No peer table found, starting fresh");
            Ok(Self::default())
        }
    }

    /// Save peer table to disk
    pub fn save(&self, data_dir: &PathBuf) -> anyhow::Result<()> {
        let path = data_dir.join("peers.json");
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(&path, content)?;
        tracing::debug!("Saved {} peers to disk", self.peers.len());
        Ok(())
    }

    /// Add a peer or update if already known
    pub fn upsert(&mut self, peer: PeerInfo) {
        let key = format!("{}:{}", peer.address, peer.port);
        self.peers.insert(key, peer);
    }

    /// Get all known peers except the given address
    pub fn get_others(&self, exclude_address: &str, exclude_port: u16) -> Vec<PeerInfo> {
        self.peers.values()
            .filter(|p| !(p.address == exclude_address && p.port == exclude_port))
            .cloned()
            .collect()
    }

    /// Get all known peers
    pub fn get_all(&self) -> Vec<PeerInfo> {
        self.peers.values().cloned().collect()
    }

    /// Get peer count
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// Merge in peers from a PeerExchange message
    pub fn merge_from_exchange(&mut self, known_peers: &[PeerInfo], self_address: &str, self_port: u16) {
        for peer in known_peers {
            // Don't add ourselves
            if peer.address == self_address && peer.port == self_port {
                continue;
            }
            self.upsert(peer.clone());
        }
    }
}

/// Peer discovery manager - wraps PeerTable with async access
pub struct PeerDiscovery {
    data_dir: PathBuf,
    table: Arc<RwLock<PeerTable>>,
}

impl PeerDiscovery {
    /// Create a new PeerDiscovery, loading existing peers from disk
    pub async fn new(data_dir: PathBuf) -> anyhow::Result<Self> {
        let table = PeerTable::load(&data_dir)?;
        Ok(Self {
            data_dir,
            table: Arc::new(RwLock::new(table)),
        })
    }

    /// Save current peer table to disk
    pub async fn persist(&self) -> anyhow::Result<()> {
        let table = self.table.read().await;
        table.save(&self.data_dir)?;
        Ok(())
    }

    /// Get all peers except self
    pub async fn get_peer_infos(&self, self_address: &str, self_port: u16) -> Vec<PeerInfo> {
        let table = self.table.read().await;
        table.get_others(self_address, self_port)
    }

    /// Add a peer
    pub async fn add_peer(&self, address: String, port: u16, name: Option<String>) {
        let mut table = self.table.write().await;
        table.upsert(PeerInfo {
            address,
            port,
            name,
            last_seen: Utc::now(),
        });
        drop(table);
        let _ = self.persist().await;
    }

    /// Merge peers from a PeerExchange message
    pub async fn merge_exchange(&self, known_peers: &[PeerInfo], self_address: &str, self_port: u16) {
        let mut table = self.table.write().await;
        table.merge_from_exchange(known_peers, self_address, self_port);
        drop(table);
        let _ = self.persist().await;
    }

    /// Build a PeerExchange gossip message from current known peers
    pub async fn build_exchange_message(
        &self,
        sender_digest: &str,
        network_name: &str,
    ) -> GossipMessage {
        let peer_infos = self.get_peer_infos("", 0).await;
        GossipMessage::new(
            sender_digest,
            GossipMessageType::PeerExchange {
                known_peers: peer_infos,
            },
            network_name,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_table_upsert() {
        let mut table = PeerTable::default();
        table.upsert(PeerInfo {
            address: "192.168.1.1".to_string(),
            port: 9400,
            name: Some("node-1".to_string()),
            last_seen: Utc::now(),
        });
        assert_eq!(table.len(), 1);
        
        // Update same peer
        table.upsert(PeerInfo {
            address: "192.168.1.1".to_string(),
            port: 9400,
            name: Some("node-1-updated".to_string()),
            last_seen: Utc::now(),
        });
        assert_eq!(table.len(), 1); // Still 1, not 2
    }

    #[test]
    fn test_peer_table_exclude_self() {
        let mut table = PeerTable::default();
        table.upsert(PeerInfo {
            address: "192.168.1.1".to_string(),
            port: 9400,
            name: None,
            last_seen: Utc::now(),
        });
        table.upsert(PeerInfo {
            address: "192.168.1.2".to_string(),
            port: 9400,
            name: None,
            last_seen: Utc::now(),
        });
        
        let others = table.get_others("192.168.1.1", 9400);
        assert_eq!(others.len(), 1);
        assert_eq!(others[0].address, "192.168.1.2");
    }
}
