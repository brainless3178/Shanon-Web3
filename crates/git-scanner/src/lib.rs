//! Git Scanner - For scanning Git repositories
//!
//! Handles cloning of remote Solana program repositories for automated audits.
//! Supports GitHub, GitLab, Bitbucket, Codeberg, and any public Git host.

use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;
use thiserror::Error;
use url::Url;

#[derive(Debug, Error)]
pub enum GitError {
    #[error("Invalid URL: {0}")]
    InvalidUrl(String),
    #[error("Git clone failed: {0}")]
    CloneFailed(String),
    #[error("IO error: {0}")]
    IoError(String),
}

pub struct GitScanner {
    temp_dir: Option<TempDir>,
}

impl GitScanner {
    pub fn new() -> Self {
        Self { temp_dir: None }
    }

    /// Clone a repository from a Git hosting URL and return the local path.
    /// Supports GitHub, GitLab, Bitbucket, Codeberg, and any valid HTTPS git URL.
    /// If `branch` is provided, only that branch is cloned.
    pub fn clone_repo(&mut self, repo_url: &str, branch: Option<&str>) -> Result<PathBuf, GitError> {
        // Validate URL
        let url = Url::parse(repo_url).map_err(|e| GitError::InvalidUrl(e.to_string()))?;
        if url.host_str().is_none() {
            return Err(GitError::InvalidUrl(
                "URL must contain a valid host".to_string(),
            ));
        }

        // Create a temporary directory for the clone
        let temp = TempDir::new().map_err(|e| GitError::IoError(e.to_string()))?;
        let path = temp.path().to_path_buf();

        // Execute git clone
        let mut cmd = Command::new("git");
        cmd.arg("clone").arg("--depth").arg("1");
        if let Some(b) = branch {
            cmd.arg("--branch").arg(b);
        }
        let output = cmd
            .arg(repo_url)
            .arg(&path)
            .output()
            .map_err(|e| GitError::IoError(e.to_string()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(GitError::CloneFailed(stderr.to_string()));
        }

        // Store temp dir so it doesn't get deleted immediately
        self.temp_dir = Some(temp);

        Ok(path)
    }

    /// Cleanup the temporary directory
    pub fn cleanup(&mut self) {
        self.temp_dir = None;
    }
}

impl Default for GitScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_git_scanner_creation() {
        let scanner = GitScanner::new();
        assert!(scanner.temp_dir.is_none());
    }

    #[test]
    fn test_git_scanner_default() {
        let scanner = GitScanner::default();
        assert!(scanner.temp_dir.is_none());
    }

    #[test]
    fn test_clone_invalid_url() {
        let mut scanner = GitScanner::new();
        let result = scanner.clone_repo("not-a-valid-url", None);
        assert!(result.is_err());
        match result.unwrap_err() {
            GitError::InvalidUrl(_) => {}
            other => panic!("Expected InvalidUrl, got: {:?}", other),
        }
    }

    #[test]
    fn test_clone_no_host_url() {
        let mut scanner = GitScanner::new();
        let result = scanner.clone_repo("file:///local/path", None);
        assert!(result.is_err());
        match result.unwrap_err() {
            // file:// URLs have no host — clone would fail on validation
            GitError::InvalidUrl(_) | GitError::CloneFailed(_) => {}
            other => panic!("Expected InvalidUrl or CloneFailed, got: {:?}", other),
        }
    }

    #[test]
    fn test_cleanup() {
        let mut scanner = GitScanner::new();
        scanner.cleanup();
        assert!(scanner.temp_dir.is_none());
    }

    #[test]
    fn test_error_display() {
        let err = GitError::InvalidUrl("bad url".to_string());
        assert!(err.to_string().contains("bad url"));
        let err = GitError::CloneFailed("failed".to_string());
        assert!(err.to_string().contains("failed"));
    }
}
