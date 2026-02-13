# ─── Stage 1: Build the Rust binary ───
FROM rust:1.83-bookworm AS builder

WORKDIR /build

# Copy workspace manifests first for dependency caching
COPY Cargo.toml Cargo.lock* ./
COPY crates/api-server/Cargo.toml crates/api-server/Cargo.toml

# Create dummy workspace members so cargo resolves the workspace
# We only need api-server, but Cargo needs all members to exist
COPY crates/ crates/
COPY programs/ programs/
COPY exploits/ exploits/

# Build only the api-server in release mode
RUN cargo build -p api-server --release --bin security-dashboard-server \
    && strip target/release/security-dashboard-server

# ─── Stage 2: Minimal runtime image ───
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the compiled binary
COPY --from=builder /build/target/release/security-dashboard-server /app/server

# Copy dashboard static files
COPY dashboard/ /app/dashboard/

# Copy audit report data
COPY production_audit_results/ /app/production_audit_results/
COPY audit_reports/ /app/audit_reports/

# Default port
ENV PORT=8089

EXPOSE 8089

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:${PORT}/api/status || exit 1

CMD ["/app/server"]
