#!/usr/bin/env bash
# Brrq L2 Testnet — One-command launch
# Usage: ./launch.sh [build|start|stop|logs|status|clean]

set -euo pipefail
cd "$(dirname "$0")"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

case "${1:-start}" in
  build)
    echo -e "${YELLOW}Building Brrq L2 Testnet...${NC}"
    docker compose -f docker/docker-compose.yml build --no-cache
    echo -e "${GREEN}Build complete.${NC}"
    ;;

  start)
    echo -e "${YELLOW}Starting Brrq L2 Testnet...${NC}"
    docker compose -f docker/docker-compose.yml up -d --build
    echo ""
    echo -e "${GREEN}Brrq L2 Testnet is running!${NC}"
    echo ""
    echo "  REST API:    http://localhost:8545/api/v1/health"
    echo "  JSON-RPC:    http://localhost:8545"
    echo "  WebSocket:   ws://localhost:8546/ws"
    echo "  P2P:         localhost:30303"
    echo ""
    echo "  Logs:        ./launch.sh logs"
    echo "  Stop:        ./launch.sh stop"
    echo "  Status:      ./launch.sh status"
    ;;

  stop)
    echo -e "${YELLOW}Stopping Brrq L2 Testnet...${NC}"
    docker compose -f docker/docker-compose.yml down
    echo -e "${GREEN}Stopped.${NC}"
    ;;

  logs)
    docker compose -f docker/docker-compose.yml logs -f --tail=100
    ;;

  status)
    echo -e "${YELLOW}Brrq L2 Testnet Status:${NC}"
    docker compose -f docker/docker-compose.yml ps
    echo ""
    # Health check
    if curl -sf http://localhost:8545/api/v1/health > /dev/null 2>&1; then
      echo -e "  API: ${GREEN}HEALTHY${NC}"
      # Get block height
      HEIGHT=$(curl -sf http://localhost:8545/api/v1/block/latest 2>/dev/null | grep -o '"height":[0-9]*' | head -1 | cut -d: -f2)
      echo "  Block Height: ${HEIGHT:-unknown}"
      # Portal stats
      PORTAL=$(curl -sf http://localhost:8545/api/v1/portal/stats 2>/dev/null)
      if [ -n "$PORTAL" ]; then
        echo "  Portal: $PORTAL"
      fi
    else
      echo -e "  API: ${RED}NOT REACHABLE${NC}"
    fi
    ;;

  clean)
    echo -e "${RED}Removing all Brrq testnet data...${NC}"
    docker compose -f docker/docker-compose.yml down -v
    echo -e "${GREEN}Clean. All data removed.${NC}"
    ;;

  *)
    echo "Usage: $0 {build|start|stop|logs|status|clean}"
    exit 1
    ;;
esac
