//! Security utilities for the analyzer
//!
//! Provides secure handling of sensitive data like API keys,
//! sandboxing considerations, and input validation.

use std::fmt;
use zeroize::Zeroize;

/// A secret value that won't be accidentally logged or printed.
///
/// The inner value is zeroed on drop for additional security.
pub struct Secret<T: Zeroize>(T);

impl<T: Zeroize> Secret<T> {
    /// Create a new secret value
    pub fn new(value: T) -> Self {
        Self(value)
    }

    /// Expose the secret value (use sparingly)
    pub fn expose(&self) -> &T {
        &self.0
    }
}

impl Secret<String> {
    /// Create from environment variable
    pub fn from_env(key: &str) -> Option<Self> {
        std::env::var(key).ok().map(Secret::new)
    }
}

impl<T: Zeroize> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secret([REDACTED])")
    }
}

impl<T: Zeroize> fmt::Display for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED]")
    }
}

/// Input validation utilities
pub mod validation {
    use std::path::Path;

    /// Maximum source file size (10 MB)
    pub const MAX_SOURCE_SIZE: usize = 10 * 1024 * 1024;

    /// Maximum path depth to prevent traversal attacks
    pub const MAX_PATH_DEPTH: usize = 50;

    /// Validate source code input
    pub fn validate_source(source: &str) -> Result<(), ValidationError> {
        if source.len() > MAX_SOURCE_SIZE {
            return Err(ValidationError::TooLarge {
                size: source.len(),
                max: MAX_SOURCE_SIZE,
            });
        }

        // Check for null bytes (potential injection)
        if source.contains('\0') {
            return Err(ValidationError::InvalidCharacter('\0'));
        }

        Ok(())
    }

    /// Validate file path (prevent traversal)
    pub fn validate_path(path: &Path) -> Result<(), ValidationError> {
        // Check for path traversal attempts
        let path_str = path.to_string_lossy();
        if path_str.contains("..") {
            return Err(ValidationError::PathTraversal);
        }

        // Check depth
        let depth = path.components().count();
        if depth > MAX_PATH_DEPTH {
            return Err(ValidationError::TooDeep {
                depth,
                max: MAX_PATH_DEPTH,
            });
        }

        Ok(())
    }

    /// Validation errors
    #[derive(Debug)]
    pub enum ValidationError {
        TooLarge { size: usize, max: usize },
        TooDeep { depth: usize, max: usize },
        InvalidCharacter(char),
        PathTraversal,
    }

    impl std::fmt::Display for ValidationError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::TooLarge { size, max } => {
                    write!(f, "Input too large: {} bytes (max: {})", size, max)
                }
                Self::TooDeep { depth, max } => {
                    write!(f, "Path too deep: {} levels (max: {})", depth, max)
                }
                Self::InvalidCharacter(c) => {
                    write!(f, "Invalid character in input: {:?}", c)
                }
                Self::PathTraversal => {
                    write!(f, "Path traversal attempt detected")
                }
            }
        }
    }

    impl std::error::Error for ValidationError {}
}

pub mod sandbox {
    //! # Sandboxing Guidelines
    //!
    //! When analyzing untrusted code, consider:
    //!
    //! 1. **Resource limits**: Use `rlimit` to cap CPU and memory
    //! 2. **Filesystem isolation**: Use a temp directory
    //! 3. **Network isolation**: No network access needed for analysis
    //! 4. **Process isolation**: Consider running in a container
    //!
    //! ## Example using nix crate
    //!
    //! ```ignore
    //! use nix::sys::resource::{setrlimit, Resource};
    //!
    //! // Limit to 60 seconds of CPU
    //! setrlimit(Resource::RLIMIT_CPU, 60, 60)?;
    //!
    //! // Limit to 1GB of memory  
    //! setrlimit(Resource::RLIMIT_AS, 1 << 30, 1 << 30)?;
    //! ```
    //!
    //! ## Container recommendation
    //!
    //! ```dockerfile
    //! FROM rust:slim
    //! RUN useradd -m analyzer
    //! USER analyzer
    //! WORKDIR /analysis
    //! COPY --chown=analyzer analyzer /usr/local/bin/
    //! CMD ["analyzer", "--sandbox"]
    //! ```
}

/// Rate limiting for LLM API calls
pub struct RateLimiter {
    /// Requests per minute
    rpm_limit: u32,
    /// Current count
    request_count: std::sync::atomic::AtomicU32,
    /// Last reset time
    last_reset: std::sync::RwLock<std::time::Instant>,
}

impl RateLimiter {
    pub fn new(rpm_limit: u32) -> Self {
        Self {
            rpm_limit,
            request_count: std::sync::atomic::AtomicU32::new(0),
            last_reset: std::sync::RwLock::new(std::time::Instant::now()),
        }
    }

    /// Check if a request is allowed
    pub fn check(&self) -> bool {
        use std::sync::atomic::Ordering;
        use std::time::Duration;

        let now = std::time::Instant::now();
        let last = *self.last_reset.read().unwrap();

        // Reset counter every minute
        if now.duration_since(last) > Duration::from_secs(60) {
            *self.last_reset.write().unwrap() = now;
            self.request_count.store(0, Ordering::Relaxed);
        }

        let count = self.request_count.fetch_add(1, Ordering::Relaxed);
        count < self.rpm_limit
    }

    /// Wait until request is allowed
    pub fn wait(&self) {
        use std::time::Duration;

        while !self.check() {
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_redaction() {
        let secret = Secret::new("super-secret-key".to_string());

        // Debug should not expose value
        let debug = format!("{:?}", secret);
        assert!(!debug.contains("super-secret"));
        assert!(debug.contains("REDACTED"));

        // Display should not expose value
        let display = format!("{}", secret);
        assert!(!display.contains("super-secret"));
        assert!(display.contains("REDACTED"));

        // Can still access value when needed
        assert_eq!(secret.expose(), "super-secret-key");
    }

    #[test]
    fn test_validation_source() {
        use validation::*;

        // Normal source is OK
        assert!(validate_source("fn main() {}").is_ok());

        // Null bytes are rejected
        assert!(matches!(
            validate_source("fn main() {\0}"),
            Err(ValidationError::InvalidCharacter('\0'))
        ));
    }

    #[test]
    fn test_validation_path() {
        use std::path::Path;
        use validation::*;

        // Normal path is OK
        assert!(validate_path(Path::new("/home/user/project/src/lib.rs")).is_ok());

        // Path traversal is rejected
        assert!(matches!(
            validate_path(Path::new("/home/user/../../../etc/passwd")),
            Err(ValidationError::PathTraversal)
        ));
    }

    #[test]
    fn test_rate_limiter() {
        let limiter = RateLimiter::new(5);

        // First 5 requests should pass
        for _ in 0..5 {
            assert!(limiter.check());
        }

        // 6th request should fail (within same minute)
        assert!(!limiter.check());
    }
}
