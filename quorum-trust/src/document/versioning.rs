use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DocumentStatus {
    Draft,
    Final,
    Forked { from: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentMeta {
    pub path: String,
    pub version: u64,
    pub status: DocumentStatus,
    pub content_hash: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deadline: Option<DateTime<Utc>>,
    pub created_by: String,
    pub last_updated_by: String,
    #[serde(default)]
    pub threshold_signature: Option<Vec<u8>>,
    #[serde(default)]
    pub group_public_key: Option<Vec<u8>>,
    #[serde(default)]
    pub frost_threshold: Option<u16>,
    #[serde(default)]
    pub frost_total: Option<u16>,
}

/// Stored in `.quorum-trust` files in each folder alongside tracked documents.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FolderRegistry {
    pub documents: HashMap<String, DocumentMeta>,
}

impl FolderRegistry {
    pub fn load(dir: &Path) -> anyhow::Result<Self> {
        let registry_path = dir.join(".quorum-trust");
        if registry_path.exists() {
            let content = std::fs::read_to_string(&registry_path)?;
            Ok(serde_json::from_str(&content)?)
        } else {
            Ok(Self::default())
        }
    }

    pub fn save(&self, dir: &Path) -> anyhow::Result<()> {
        let registry_path = dir.join(".quorum-trust");
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(registry_path, content)?;
        Ok(())
    }

    pub fn register_document(&mut self, meta: DocumentMeta) {
        self.documents.insert(meta.path.clone(), meta);
    }

    pub fn get_document(&self, filename: &str) -> Option<&DocumentMeta> {
        self.documents.get(filename)
    }

    pub fn increment_version(&mut self, filename: &str, updater: &str, new_hash: &str) -> Option<u64> {
        if let Some(meta) = self.documents.get_mut(filename) {
            meta.version += 1;
            meta.updated_at = Utc::now();
            meta.last_updated_by = updater.to_string();
            meta.content_hash = new_hash.to_string();
            Some(meta.version)
        } else {
            None
        }
    }

    pub fn mark_final(&mut self, filename: &str) -> bool {
        if let Some(meta) = self.documents.get_mut(filename) {
            meta.status = DocumentStatus::Final;
            meta.updated_at = Utc::now();
            true
        } else {
            false
        }
    }

    pub fn check_deadlines(&mut self) {
        let now = Utc::now();
        for meta in self.documents.values_mut() {
            if meta.status == DocumentStatus::Draft {
                if let Some(deadline) = meta.deadline {
                    if now >= deadline {
                        meta.status = DocumentStatus::Final;
                    }
                }
            }
        }
    }

    pub fn tracked_files(&self) -> Vec<&str> {
        self.documents.keys().map(|s| s.as_str()).collect()
    }
}

impl DocumentMeta {
    pub fn new(path: &str, content_hash: &str, created_by: &str) -> Self {
        let now = Utc::now();
        Self {
            path: path.to_string(),
            version: 1,
            status: DocumentStatus::Draft,
            content_hash: content_hash.to_string(),
            created_at: now,
            updated_at: now,
            deadline: None,
            created_by: created_by.to_string(),
            last_updated_by: created_by.to_string(),
            threshold_signature: None,
            group_public_key: None,
            frost_threshold: None,
            frost_total: None,
        }
    }

    pub fn with_deadline(mut self, deadline: DateTime<Utc>) -> Self {
        self.deadline = Some(deadline);
        self
    }

    pub fn is_final(&self) -> bool {
        self.status == DocumentStatus::Final
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_folder_registry_save_load() {
        let dir = TempDir::new().unwrap();
        let mut reg = FolderRegistry::default();
        let meta = DocumentMeta::new("test.md", "hash123", "alice");
        reg.register_document(meta);
        reg.save(dir.path()).unwrap();

        let loaded = FolderRegistry::load(dir.path()).unwrap();
        assert!(loaded.get_document("test.md").is_some());
    }

    #[test]
    fn test_version_increment() {
        let mut reg = FolderRegistry::default();
        reg.register_document(DocumentMeta::new("doc.md", "h1", "alice"));
        assert_eq!(reg.increment_version("doc.md", "bob", "h2"), Some(2));
        assert_eq!(reg.get_document("doc.md").unwrap().version, 2);
    }

    #[test]
    fn test_mark_final() {
        let mut reg = FolderRegistry::default();
        reg.register_document(DocumentMeta::new("doc.md", "h1", "alice"));
        assert!(reg.mark_final("doc.md"));
        assert!(reg.get_document("doc.md").unwrap().is_final());
    }

    #[test]
    fn test_deadline_auto_finalize() {
        let mut reg = FolderRegistry::default();
        let past = Utc::now() - chrono::Duration::hours(1);
        let meta = DocumentMeta::new("doc.md", "h1", "alice").with_deadline(past);
        reg.register_document(meta);
        reg.check_deadlines();
        assert!(reg.get_document("doc.md").unwrap().is_final());
    }
}
