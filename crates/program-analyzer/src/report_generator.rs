use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportGenerator {
    // Placeholder configuration fields
    pub output_format: String,
    pub include_code_snippets: bool,
}

impl ReportGenerator {
    pub fn new(output_format: String, include_code_snippets: bool) -> Self {
        Self {
            output_format,
            include_code_snippets,
        }
    }

    pub fn generate_report<T: Serialize>(
        &self,
        data: &T,
        output_path: &Path,
    ) -> Result<(), std::io::Error> {
        let content = if self.output_format == "json" {
            serde_json::to_string_pretty(data)?
        } else {
            // Fallback for non-JSON: currently unimplemented or default serialization
            format!("{:#?}", serde_json::to_value(data)?)
        };

        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent)?;
        }

        fs::write(output_path, content)?;
        Ok(())
    }
}
