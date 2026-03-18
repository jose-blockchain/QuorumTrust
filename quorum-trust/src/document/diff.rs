use serde::{Deserialize, Serialize};
use similar::{ChangeTag, TextDiff};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileDiff {
    pub path: String,
    pub unified_diff: String,
    pub additions: usize,
    pub deletions: usize,
}

impl FileDiff {
    pub fn compute(path: &str, old_content: &str, new_content: &str) -> Self {
        let diff = TextDiff::from_lines(old_content, new_content);
        let unified = diff
            .unified_diff()
            .context_radius(3)
            .header(&format!("a/{path}"), &format!("b/{path}"))
            .to_string();

        let mut additions = 0;
        let mut deletions = 0;
        for change in diff.iter_all_changes() {
            match change.tag() {
                ChangeTag::Insert => additions += 1,
                ChangeTag::Delete => deletions += 1,
                ChangeTag::Equal => {}
            }
        }

        Self {
            path: path.to_string(),
            unified_diff: unified,
            additions,
            deletions,
        }
    }

    /// Apply the stored unified diff to old content and return patched content.
    pub fn apply(&self, old_content: &str) -> anyhow::Result<String> {
        let patch = diffy::Patch::from_str(&self.unified_diff)
            .map_err(|e| anyhow::anyhow!("Failed to parse patch: {e}"))?;
        diffy::apply(old_content, &patch)
            .map_err(|e| anyhow::anyhow!("Failed to apply patch: {e}"))
    }

    pub fn is_empty(&self) -> bool {
        self.additions == 0 && self.deletions == 0
    }
}

/// Save a diff file alongside the original document.
pub fn save_diff_file(
    docs_dir: &std::path::Path,
    relative_path: &str,
    diff: &FileDiff,
    proposer: &str,
) -> anyhow::Result<std::path::PathBuf> {
    let file_dir = docs_dir.join(
        std::path::Path::new(relative_path)
            .parent()
            .unwrap_or(std::path::Path::new("")),
    );
    std::fs::create_dir_all(&file_dir)?;

    let stem = std::path::Path::new(relative_path)
        .file_name()
        .unwrap_or_default()
        .to_string_lossy();
    let timestamp = chrono::Utc::now().format("%Y%m%d%H%M%S");
    let diff_filename = format!("{stem}.{timestamp}.{}.diff", &proposer[..8.min(proposer.len())]);
    let diff_path = file_dir.join(&diff_filename);
    std::fs::write(&diff_path, &diff.unified_diff)?;
    Ok(diff_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_diff() {
        let old = "line1\nline2\nline3\n";
        let new = "line1\nmodified\nline3\nadded\n";
        let diff = FileDiff::compute("test.md", old, new);
        assert_eq!(diff.additions, 2);
        assert_eq!(diff.deletions, 1);
        assert!(!diff.unified_diff.is_empty());
    }

    #[test]
    fn test_empty_diff() {
        let content = "same\n";
        let diff = FileDiff::compute("test.md", content, content);
        assert!(diff.is_empty());
    }

    #[test]
    fn test_apply_diff() {
        let old = "line1\nline2\nline3\n";
        let new = "line1\nmodified\nline3\n";
        let diff = FileDiff::compute("test.md", old, new);
        let result = diff.apply(old).unwrap();
        assert_eq!(result, new);
    }

    #[test]
    fn test_save_diff_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let diff = FileDiff::compute("sub/doc.md", "old\n", "new\n");
        let path = save_diff_file(dir.path(), "sub/doc.md", &diff, "abcdef1234").unwrap();
        assert!(path.exists());
        assert!(path.to_string_lossy().contains(".diff"));
    }

    #[test]
    fn test_diff_empty_to_content() {
        let old = "";
        let new = "first\nsecond\n";
        let diff = FileDiff::compute("new.txt", old, new);
        assert_eq!(diff.additions, 2);
        assert_eq!(diff.deletions, 0);
        assert!(!diff.is_empty());
        let result = diff.apply(old).unwrap();
        assert_eq!(result, new);
    }

    #[test]
    fn test_diff_content_to_empty() {
        let old = "line1\nline2\n";
        let new = "";
        let diff = FileDiff::compute("del.txt", old, new);
        assert_eq!(diff.additions, 0);
        assert_eq!(diff.deletions, 2);
        let result = diff.apply(old).unwrap();
        assert_eq!(result, new);
    }

    #[test]
    fn test_diff_path_in_header() {
        let diff = FileDiff::compute("a/b/file.rs", "x\n", "y\n");
        assert!(diff.unified_diff.contains("a/a/b/file.rs"));
        assert!(diff.unified_diff.contains("b/a/b/file.rs"));
    }

    #[test]
    fn test_diff_replace_entire_content() {
        let old = "old1\nold2\nold3\n";
        let new = "new1\nnew2\n";
        let diff = FileDiff::compute("full.md", old, new);
        assert_eq!(diff.additions, 2);
        assert_eq!(diff.deletions, 3);
        let result = diff.apply(old).unwrap();
        assert_eq!(result, new);
    }

    #[test]
    fn test_diff_apply_fails_on_wrong_base() {
        let old = "line1\nline2\n";
        let new = "line1\nmodified\n";
        let diff = FileDiff::compute("x.md", old, new);
        assert!(diff.apply("wrong\nbase\n").is_err());
    }

    #[test]
    fn test_diff_insert_at_start() {
        let old = "original\n";
        let new = "prepend\noriginal\n";
        let diff = FileDiff::compute("pre.md", old, new);
        assert_eq!(diff.additions, 1);
        assert_eq!(diff.deletions, 0);
        assert_eq!(diff.apply(old).unwrap(), new);
    }

    #[test]
    fn test_diff_insert_at_end() {
        let old = "original\n";
        let new = "original\nappend\n";
        let diff = FileDiff::compute("post.md", old, new);
        assert_eq!(diff.additions, 1);
        assert_eq!(diff.deletions, 0);
        assert_eq!(diff.apply(old).unwrap(), new);
    }

    #[test]
    fn test_diff_single_line_change() {
        let old = "one line\n";
        let new = "one changed line\n";
        let diff = FileDiff::compute("single.md", old, new);
        assert_eq!(diff.additions, 1);
        assert_eq!(diff.deletions, 1);
        assert_eq!(diff.apply(old).unwrap(), new);
    }

    #[test]
    fn test_save_diff_file_short_proposer() {
        let dir = tempfile::TempDir::new().unwrap();
        let diff = FileDiff::compute("root.md", "a\n", "b\n");
        let path = save_diff_file(dir.path(), "root.md", &diff, "ab").unwrap();
        assert!(path.exists());
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("---"));
        assert!(content.contains("+++"));
    }
}
