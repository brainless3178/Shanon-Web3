#!/usr/bin/env bash
# Test script for NVIDIA/Kimi K2.5 API integration

set -e

echo "🧪 Testing NVIDIA/Kimi K2.5 API Integration"
echo "=========================================="
echo ""

# Check if API key is set
if [ -z "$NVIDIA_API_KEY" ]; then
    echo "⚠️  NVIDIA_API_KEY environment variable not set"
    echo "   Using hardcoded key from user request for testing..."
    export NVIDIA_API_KEY="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"
fi

echo "✅ API Key: ${NVIDIA_API_KEY:0:15}..."
echo "✅ Model: moonshotai/kimi-k2.5"
echo ""

# Create a simple Rust test program
cat > /tmp/test_kimi_api.rs << 'EOF'
use serde_json::json;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let api_key = std::env::var("NVIDIA_API_KEY")
        .expect("NVIDIA_API_KEY must be set");
    
    let client = reqwest::Client::new();
    
    let payload = json!({
        "model": "moonshotai/kimi-k2.5",
        "messages": [{
            "role": "user",
            "content": "Explain in one sentence what makes Solana's account model different from Ethereum's."
        }],
        "max_tokens": 16384,
        "temperature": 1.0,
        "top_p": 1.0,
        "stream": false,
        "chat_template_kwargs": {"thinking": true}
    });
    
    println!("📡 Sending request to NVIDIA API...");
    
    let response = client
        .post("https://integrate.api.nvidia.com/v1/chat/completions")
        .header("Authorization", format!("Bearer {}", api_key))
        .header("Accept", "application/json")
        .header("Content-Type", "application/json")
        .json(&payload)
        .send()
        .await?;
    
    let status = response.status();
    println!("📊 Response Status: {}", status);
    
    if status.is_success() {
        let body: serde_json::Value = response.json().await?;
        
        if let Some(choices) = body.get("choices").and_then(|c| c.as_array()) {
            if let Some(first_choice) = choices.first() {
                if let Some(content) = first_choice.get("message")
                    .and_then(|m| m.get("content"))
                    .and_then(|c| c.as_str()) {
                    println!("\n✅ API Response:");
                    println!("─────────────────");
                    println!("{}", content);
                    println!("─────────────────");
                    println!("\n🎉 SUCCESS: Kimi K2.5 API is working!");
                    return Ok(());
                }
            }
        }
        
        println!("⚠️  Unexpected response format:");
        println!("{}", serde_json::to_string_pretty(&body)?);
    } else {
        let error_text = response.text().await?;
        println!("❌ API Error: {}", error_text);
        return Err(format!("API returned error status: {}", status).into());
    }
    
    Ok(())
}
EOF

echo "🔨 Compiling test program..."
cd /tmp
rustc --edition 2021 test_kimi_api.rs \
    --extern tokio=/home/elliot/Music/hackathon/target/debug/deps/libtokio-*.rlib \
    --extern reqwest=/home/elliot/Music/hackathon/target/debug/deps/libreqwest-*.rlib \
    --extern serde_json=/home/elliot/Music/hackathon/target/debug/deps/libserde_json-*.rlib \
    -L /home/elliot/Music/hackathon/target/debug/deps \
    2>/dev/null || {
        echo "⚠️  Compilation failed, using cargo script instead..."
        
        # Fallback: use cargo script
        cat > /tmp/Cargo.toml << 'CARGO_EOF'
[package]
name = "test-kimi"
version = "0.1.0"
edition = "2021"

[dependencies]
tokio = { version = "1", features = ["full"] }
reqwest = { version = "0.11", features = ["json"] }
serde_json = "1.0"
CARGO_EOF
        
        mkdir -p /tmp/src
        mv /tmp/test_kimi_api.rs /tmp/src/main.rs
        
        echo "🚀 Running test via cargo..."
        cargo run --manifest-path /tmp/Cargo.toml --quiet
        exit $?
    }

echo "🚀 Running test..."
/tmp/test_kimi_api

echo ""
echo "✅ Test complete!"
