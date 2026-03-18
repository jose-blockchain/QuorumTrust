use crate::document::diff::FileDiff;
use crate::document::versioning::{DocumentMeta, DocumentStatus, FolderRegistry};
use anyhow::{bail, Result};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub struct DocumentManager {
    documents_root: PathBuf,
    registries: HashMap<PathBuf, FolderRegistry>,
}

impl DocumentManager {
    pub fn new(documents_root: PathBuf) -> Self {
        Self {
            documents_root,
            registries: HashMap::new(),
        }
    }

    pub fn root(&self) -> &Path {
        &self.documents_root
    }

    pub fn ensure_root(&self) -> Result<()> {
        std::fs::create_dir_all(&self.documents_root)?;
        Ok(())
    }

    fn get_or_load_registry(&mut self, folder: &Path) -> Result<&mut FolderRegistry> {
        if !self.registries.contains_key(folder) {
            let reg = FolderRegistry::load(folder)?;
            self.registries.insert(folder.to_path_buf(), reg);
        }
        Ok(self.registries.get_mut(folder).unwrap())
    }

    fn folder_for_file(&self, relative_path: &str) -> PathBuf {
        let full = self.documents_root.join(relative_path);
        full.parent()
            .unwrap_or(&self.documents_root)
            .to_path_buf()
    }

    pub fn add_file(
        &mut self,
        relative_path: &str,
        content: &str,
        creator_digest: &str,
    ) -> Result<DocumentMeta> {
        let full_path = self.documents_root.join(relative_path);
        if full_path.exists() {
            bail!("File already exists: {relative_path}");
        }

        if let Some(parent) = full_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&full_path, content)?;

        let hash = Self::hash_content(content);
        let meta = DocumentMeta::new(relative_path, &hash, creator_digest);

        let folder = self.folder_for_file(relative_path);
        let reg = self.get_or_load_registry(&folder)?;
        reg.register_document(meta.clone());
        reg.save(&folder)?;

        Ok(meta)
    }

    pub fn read_file(&self, relative_path: &str) -> Result<String> {
        let full_path = self.documents_root.join(relative_path);
        Ok(std::fs::read_to_string(full_path)?)
    }

    pub fn compute_diff(
        &self,
        relative_path: &str,
        new_content: &str,
    ) -> Result<FileDiff> {
        let old_content = self.read_file(relative_path)?;
        Ok(FileDiff::compute(relative_path, &old_content, new_content))
    }

    pub fn apply_edit(
        &mut self,
        relative_path: &str,
        diff: &FileDiff,
        updater_digest: &str,
    ) -> Result<u64> {
        let folder = self.folder_for_file(relative_path);

        {
            let reg = self.get_or_load_registry(&folder)?;
            if let Some(meta) = reg.get_document(relative_path) {
                if meta.is_final() {
                    bail!("Document is finalized, cannot edit: {relative_path}");
                }
            }
        }

        let old_content = self.read_file(relative_path)?;
        let new_content = diff.apply(&old_content)?;
        let new_hash = Self::hash_content(&new_content);

        let full_path = self.documents_root.join(relative_path);
        std::fs::write(&full_path, &new_content)?;

        let reg = self.get_or_load_registry(&folder)?;
        let version = reg
            .increment_version(relative_path, updater_digest, &new_hash)
            .ok_or_else(|| anyhow::anyhow!("Document not tracked: {relative_path}"))?;
        reg.save(&folder)?;

        Ok(version)
    }

    pub fn remove_file(&mut self, relative_path: &str) -> Result<()> {
        let full_path = self.documents_root.join(relative_path);
        if full_path.exists() {
            std::fs::remove_file(&full_path)?;
        }

        let folder = self.folder_for_file(relative_path);
        let reg = self.get_or_load_registry(&folder)?;
        reg.documents.remove(relative_path);
        reg.save(&folder)?;
        Ok(())
    }

    /// Rename a file (for local renames or ChangeFileName application).
    /// Updates registry and moves the file on disk.
    pub fn rename_file(&mut self, old_path: &str, new_path: &str) -> Result<()> {
        let old_full = self.documents_root.join(old_path);
        let new_full = self.documents_root.join(new_path);
        if !old_full.exists() {
            bail!("File not found: {old_path}");
        }
        if new_full.exists() {
            bail!("Target already exists: {new_path}");
        }
        if let Some(parent) = new_full.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let old_folder = self.folder_for_file(old_path);
        let reg = self.get_or_load_registry(&old_folder)?;
        let meta = reg.documents.remove(old_path).ok_or_else(|| anyhow::anyhow!("Document not tracked: {old_path}"))?;
        reg.save(&old_folder)?;

        std::fs::rename(&old_full, &new_full)?;

        let mut new_meta = meta.clone();
        new_meta.path = new_path.to_string();
        let new_folder = self.folder_for_file(new_path);
        let reg = self.get_or_load_registry(&new_folder)?;
        reg.documents.insert(new_path.to_string(), new_meta);
        reg.save(&new_folder)?;

        Ok(())
    }

    pub fn mark_final(&mut self, relative_path: &str) -> Result<()> {
        let folder = self.folder_for_file(relative_path);
        let reg = self.get_or_load_registry(&folder)?;
        if !reg.mark_final(relative_path) {
            bail!("Document not found: {relative_path}");
        }
        reg.save(&folder)?;
        Ok(())
    }

    pub fn fork_file(
        &mut self,
        relative_path: &str,
        new_name: Option<&str>,
        forker_digest: &str,
    ) -> Result<String> {
        let content = self.read_file(relative_path)?;

        let new_path = match new_name {
            Some(name) => {
                let parent = Path::new(relative_path)
                    .parent()
                    .unwrap_or(Path::new(""));
                parent.join(name).to_string_lossy().to_string()
            }
            None => {
                let stem = Path::new(relative_path)
                    .file_stem()
                    .unwrap_or_default()
                    .to_string_lossy();
                let ext = Path::new(relative_path)
                    .extension()
                    .map(|e| format!(".{}", e.to_string_lossy()))
                    .unwrap_or_default();
                let suffix = chrono::Utc::now().format("%Y%m%d%H%M%S");
                let parent = Path::new(relative_path)
                    .parent()
                    .unwrap_or(Path::new(""));
                parent
                    .join(format!("{stem}-fork-{suffix}{ext}"))
                    .to_string_lossy()
                    .to_string()
            }
        };

        let full_path = self.documents_root.join(&new_path);
        if full_path.exists() {
            bail!("Fork target already exists: {new_path}");
        }
        if let Some(parent) = full_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&full_path, &content)?;

        let hash = Self::hash_content(&content);
        let mut meta = DocumentMeta::new(&new_path, &hash, forker_digest);
        meta.status = DocumentStatus::Forked {
            from: relative_path.to_string(),
        };

        let folder = self.folder_for_file(&new_path);
        let reg = self.get_or_load_registry(&folder)?;
        reg.register_document(meta);
        reg.save(&folder)?;

        Ok(new_path)
    }

    pub fn list_files(&mut self) -> Result<Vec<FileListEntry>> {
        let mut entries = Vec::new();
        self.list_files_recursive(&self.documents_root.clone(), "", &mut entries)?;
        Ok(entries)
    }

    fn list_files_recursive(
        &mut self,
        dir: &Path,
        prefix: &str,
        entries: &mut Vec<FileListEntry>,
    ) -> Result<()> {
        if !dir.exists() {
            return Ok(());
        }

        let reg = FolderRegistry::load(dir).unwrap_or_default();

        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();

            if name.starts_with('.') {
                continue;
            }

            let relative = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };

            if entry.file_type()?.is_dir() {
                entries.push(FileListEntry {
                    path: relative.clone(),
                    is_dir: true,
                    tracking_status: TrackingStatus::NotTracked,
                    version: None,
                    doc_status: None,
                    is_network: false,
                    threshold_signature_hex: None,
                    frost_threshold: None,
                    frost_total: None,
                    group_public_key_hex: None,
                });
                self.list_files_recursive(&entry.path(), &relative, entries)?;
            } else if !name.ends_with(".diff") {
                let tracking = if reg.get_document(&relative).is_some() {
                    let meta = reg.get_document(&relative).unwrap();
                    entries.push(FileListEntry {
                        path: relative,
                        is_dir: false,
                        tracking_status: TrackingStatus::Tracked,
                        version: Some(meta.version),
                        doc_status: Some(meta.status.clone()),
                        is_network: false,
                        threshold_signature_hex: meta.threshold_signature.as_ref().map(hex::encode),
                        frost_threshold: meta.frost_threshold,
                        frost_total: meta.frost_total,
                        group_public_key_hex: meta.group_public_key.as_ref().map(hex::encode),
                    });
                    continue;
                } else {
                    TrackingStatus::NotTracked
                };

                entries.push(FileListEntry {
                    path: relative,
                    is_dir: false,
                    tracking_status: tracking,
                    version: None,
                    doc_status: None,
                    is_network: false,
                    threshold_signature_hex: None,
                    frost_threshold: None,
                    frost_total: None,
                    group_public_key_hex: None,
                });
            }
        }
        Ok(())
    }

    pub fn check_all_deadlines(&mut self) -> Result<()> {
        let root = self.documents_root.clone();
        self.check_deadlines_recursive(&root)
    }

    fn check_deadlines_recursive(&mut self, dir: &Path) -> Result<()> {
        if !dir.exists() {
            return Ok(());
        }
        let reg = self.get_or_load_registry(dir)?;
        reg.check_deadlines();
        let reg_clone = reg.clone();
        reg_clone.save(dir)?;

        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                let name = entry.file_name().to_string_lossy().to_string();
                if !name.starts_with('.') {
                    self.check_deadlines_recursive(&entry.path())?;
                }
            }
        }
        Ok(())
    }

    /// Get the content hash of a tracked file.
    pub fn content_hash(&mut self, relative_path: &str) -> anyhow::Result<String> {
        let content = self.read_file(relative_path)?;
        Ok(Self::hash_content(&content))
    }

    /// Store a FROST threshold signature on a finalized document.
    pub fn set_threshold_signature(
        &mut self,
        relative_path: &str,
        signature: Vec<u8>,
        group_public_key: Vec<u8>,
        threshold: u16,
        total: u16,
    ) {
        let folder = self.folder_for_file(relative_path);
        if let Ok(reg) = self.get_or_load_registry(&folder) {
            if let Some(meta) = reg.documents.get_mut(relative_path) {
                meta.threshold_signature = Some(signature);
                meta.group_public_key = Some(group_public_key);
                meta.frost_threshold = Some(threshold);
                meta.frost_total = Some(total);
                let _ = reg.save(&folder);
            }
        }
    }

    fn hash_content(content: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        hex::encode(hasher.finalize())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TrackingStatus {
    Tracked,
    PendingVote,
    NotTracked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileListEntry {
    pub path: String,
    pub is_dir: bool,
    pub tracking_status: TrackingStatus,
    pub version: Option<u64>,
    pub doc_status: Option<DocumentStatus>,
    /// Whether this file has been accepted to the network (AddFile voted in).
    #[serde(default)]
    pub is_network: bool,
    #[serde(default)]
    pub threshold_signature_hex: Option<String>,
    #[serde(default)]
    pub frost_threshold: Option<u16>,
    #[serde(default)]
    pub frost_total: Option<u16>,
    #[serde(default)]
    pub group_public_key_hex: Option<String>,
}

use serde::{Deserialize, Serialize};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_and_read_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut mgr = DocumentManager::new(dir.path().to_path_buf());
        mgr.add_file("test.md", "# Hello\n", "alice").unwrap();
        let content = mgr.read_file("test.md").unwrap();
        assert_eq!(content, "# Hello\n");
    }

    #[test]
    fn test_edit_file_via_diff() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut mgr = DocumentManager::new(dir.path().to_path_buf());
        mgr.add_file("doc.md", "line1\nline2\n", "alice").unwrap();
        let diff = mgr.compute_diff("doc.md", "line1\nmodified\n").unwrap();
        let ver = mgr.apply_edit("doc.md", &diff, "bob").unwrap();
        assert_eq!(ver, 2);
        assert_eq!(mgr.read_file("doc.md").unwrap(), "line1\nmodified\n");
    }

    #[test]
    fn test_fork_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut mgr = DocumentManager::new(dir.path().to_path_buf());
        mgr.add_file("doc.md", "content\n", "alice").unwrap();
        let new_path = mgr
            .fork_file("doc.md", Some("doc-v2.md"), "bob")
            .unwrap();
        assert_eq!(new_path, "doc-v2.md");
        assert_eq!(mgr.read_file("doc-v2.md").unwrap(), "content\n");
    }

    #[test]
    fn test_cannot_edit_final_doc() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut mgr = DocumentManager::new(dir.path().to_path_buf());
        mgr.add_file("doc.md", "content\n", "alice").unwrap();
        mgr.mark_final("doc.md").unwrap();
        let diff = FileDiff::compute("doc.md", "content\n", "new\n");
        assert!(mgr.apply_edit("doc.md", &diff, "bob").is_err());
    }
}
