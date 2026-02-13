//! Hackathon Forum Client
//!
//! Real HTTP client for posting audit results to the hackathon forum.

use serde::{Deserialize, Serialize};

pub struct HackathonClient {
    client: reqwest::Client,
    api_key: String,
    api_url: String,
}

#[derive(Debug, Serialize)]
struct CreatePostRequest {
    title: String,
    body: String,
    tags: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct CreatePostResponse {
    id: String,
    url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ApiError {
    message: String,
}

impl HackathonClient {
    /// Create a new hackathon client
    pub fn new(api_key: String, api_url: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            api_key,
            api_url,
        }
    }

    /// Create a new post on the hackathon forum
    pub async fn create_post(
        &self,
        title: &str,
        body: &str,
        tags: &[&str],
    ) -> Result<String, String> {
        let request = CreatePostRequest {
            title: title.to_string(),
            body: body.to_string(),
            tags: tags.iter().map(|s| s.to_string()).collect(),
        };

        let response = self
            .client
            .post(format!("{}/api/posts", self.api_url))
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await
            .map_err(|e| format!("HTTP request failed: {}", e))?;

        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|e| format!("Failed to read response: {}", e))?;

        if !status.is_success() {
            if let Ok(error) = serde_json::from_str::<ApiError>(&body) {
                return Err(format!("API error ({}): {}", status, error.message));
            }
            return Err(format!("API error ({}): {}", status, body));
        }

        let result: CreatePostResponse =
            serde_json::from_str(&body).map_err(|e| format!("Failed to parse response: {}", e))?;

        Ok(result.id)
    }

    /// Post an update to an existing post
    pub async fn post_update(
        &self,
        post_id: &str,
        title: &str,
        body: &str,
        tags: &[&str],
    ) -> Result<String, String> {
        let request = CreatePostRequest {
            title: title.to_string(),
            body: body.to_string(),
            tags: tags.iter().map(|s| s.to_string()).collect(),
        };

        let response = self
            .client
            .put(format!("{}/api/posts/{}", self.api_url, post_id))
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await
            .map_err(|e| format!("HTTP request failed: {}", e))?;

        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|e| format!("Failed to read response: {}", e))?;

        if !status.is_success() {
            return Err(format!("API error ({}): {}", status, body));
        }

        let result: CreatePostResponse =
            serde_json::from_str(&body).map_err(|e| format!("Failed to parse response: {}", e))?;

        Ok(result.id)
    }

    /// Submit audit results as a formatted post
    pub async fn submit_audit_results(
        &self,
        program_name: &str,
        findings_count: usize,
        critical_count: usize,
        high_count: usize,
        report_markdown: &str,
    ) -> Result<String, String> {
        let title = format!(
            "🔍 Security Audit: {} - {} findings ({} Critical, {} High)",
            program_name, findings_count, critical_count, high_count
        );

        let tags = ["security-audit", "solana", "automated-analysis"];

        self.create_post(
            &title,
            report_markdown,
            &tags,
        )
        .await
    }
}

// Re-export for backward compatibility
pub type ForumClient = HackathonClient;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let client = HackathonClient::new(
            "test-api-key".to_string(),
            "https://example.com".to_string(),
        );
        assert_eq!(client.api_key, "test-api-key");
        assert_eq!(client.api_url, "https://example.com");
    }

    #[test]
    fn test_forum_client_alias() {
        let _client: ForumClient =
            HackathonClient::new("key".to_string(), "https://example.com".to_string());
    }

    #[test]
    fn test_create_post_request_serialization() {
        let request = CreatePostRequest {
            title: "Test Title".to_string(),
            body: "Test Body".to_string(),
            tags: vec!["tag1".to_string(), "tag2".to_string()],
        };
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("Test Title"));
        assert!(json.contains("tag1"));
    }

    #[test]
    fn test_api_error_deserialization() {
        let json = r#"{"message": "Not Found"}"#;
        let err: ApiError = serde_json::from_str(json).unwrap();
        assert_eq!(err.message, "Not Found");
    }
}
