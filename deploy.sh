#!/usr/bin/env bash
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Security Swarm Dashboard — Deploy Script
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
set -euo pipefail

CYAN='\033[0;36m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()   { echo -e "${RED}[ERR]${NC}   $*"; exit 1; }

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$PROJECT_DIR"

usage() {
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}  🛡️  Security Swarm Deploy Options${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo "  Usage: $0 <target>"
    echo ""
    echo "  Targets:"
    echo "    fly         Deploy to Fly.io (recommended, free tier)"
    echo "    railway     Deploy to Railway (easy, $5/mo hobby)"
    echo "    render      Deploy to Render (free tier available)"
    echo "    docker      Build Docker image locally"
    echo "    compose     Run with Docker Compose (local/VPS)"
    echo "    binary      Build release binary + bundle for scp"
    echo ""
    exit 0
}

[[ $# -lt 1 ]] && usage

case "$1" in

  fly)
    info "Deploying to Fly.io..."
    command -v flyctl >/dev/null 2>&1 || err "Install flyctl first: curl -L https://fly.io/install.sh | sh"
    
    if ! flyctl apps list 2>/dev/null | grep -q "solana-security-swarm"; then
        info "Creating new Fly app..."
        flyctl launch --copy-config --no-deploy --name solana-security-swarm
    fi
    
    flyctl deploy --ha=false
    ok "Deployed! Run 'flyctl open' to view your dashboard"
    flyctl status
    ;;

  railway)
    info "Deploying to Railway..."
    command -v railway >/dev/null 2>&1 || err "Install Railway CLI: npm i -g @railway/cli"
    
    railway login 2>/dev/null || true
    railway init 2>/dev/null || true
    railway up --detach
    ok "Deployed to Railway!"
    railway open 2>/dev/null || info "Check your Railway dashboard for the URL"
    ;;

  render)
    info "Preparing for Render deployment..."
    echo ""
    echo -e "${YELLOW}Render deploys via GitHub. Push this repo then:${NC}"
    echo "  1. Go to https://dashboard.render.com/new/web-service"
    echo "  2. Connect your GitHub repo"  
    echo "  3. Settings:"
    echo "     Runtime:     Docker"
    echo "     Region:      Oregon (US West)"
    echo "     Plan:        Free / Starter"
    echo "     Port:        8089"
    echo "  4. Click 'Create Web Service'"
    echo ""
    ok "Dockerfile and config are ready for Render"
    ;;

  docker)
    info "Building Docker image..."
    docker build -t solana-security-swarm:latest .
    ok "Image built: solana-security-swarm:latest"
    echo ""
    echo "  Run locally:  docker run -p 8089:8089 solana-security-swarm:latest"
    echo "  Push to hub:  docker tag solana-security-swarm:latest <your-registry>/solana-security-swarm:latest"
    echo "                docker push <your-registry>/solana-security-swarm:latest"
    ;;

  compose)
    info "Starting with Docker Compose..."
    docker compose up -d --build
    ok "Running at http://localhost:8089"
    docker compose logs -f
    ;;

  binary)
    info "Building release binary bundle..."
    cargo build -p api-server --release
    
    BUNDLE_DIR="$PROJECT_DIR/deploy-bundle"
    rm -rf "$BUNDLE_DIR"
    mkdir -p "$BUNDLE_DIR"
    
    cp target/release/security-dashboard-server "$BUNDLE_DIR/"
    cp -r dashboard "$BUNDLE_DIR/"
    cp -r production_audit_results "$BUNDLE_DIR/"
    cp -r audit_reports "$BUNDLE_DIR/"
    
    # Create a simple start script
    cat > "$BUNDLE_DIR/start.sh" << 'STARTEOF'
#!/usr/bin/env bash
cd "$(dirname "$0")"
export PORT="${PORT:-8089}"
echo "🛡️  Starting Security Swarm Dashboard on port $PORT..."
./security-dashboard-server
STARTEOF
    chmod +x "$BUNDLE_DIR/start.sh"
    
    # Create a tarball
    cd "$PROJECT_DIR"
    tar -czf deploy-bundle.tar.gz -C deploy-bundle .
    BUNDLE_SIZE=$(du -sh deploy-bundle.tar.gz | cut -f1)
    
    ok "Bundle ready: deploy-bundle.tar.gz ($BUNDLE_SIZE)"
    echo ""
    echo "  Deploy to any VPS:"
    echo "    scp deploy-bundle.tar.gz user@server:~/"
    echo "    ssh user@server 'mkdir -p app && cd app && tar xzf ~/deploy-bundle.tar.gz && ./start.sh'"
    ;;

  *)
    warn "Unknown target: $1"
    usage
    ;;
esac
