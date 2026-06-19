#!/usr/bin/env bash
# ==============================================================
#  SSO Vulnerability Lab — Setup Script
# ==============================================================
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

banner() {
  echo -e "${CYAN}"
  echo "  ╔══════════════════════════════════════════════════════════╗"
  echo "  ║     SSO / SAML / OpenID Vulnerability Lab v1.0          ║"
  echo "  ║     Bug Bounty & Penetration Testing Training           ║"
  echo "  ╚══════════════════════════════════════════════════════════╝"
  echo -e "${RESET}"
}

check_deps() {
  echo -e "${BOLD}[*] Checking dependencies...${RESET}"
  for cmd in docker curl python3; do
    if command -v "$cmd" &>/dev/null; then
      echo -e "  ${GREEN}✓${RESET} $cmd found"
    else
      echo -e "  ${RED}✗${RESET} $cmd not found — please install it"
      exit 1
    fi
  done

  # Check docker compose (v2)
  if docker compose version &>/dev/null 2>&1; then
    COMPOSE_CMD="docker compose"
  elif docker-compose version &>/dev/null 2>&1; then
    COMPOSE_CMD="docker-compose"
  else
    echo -e "  ${RED}✗${RESET} docker compose not found"
    exit 1
  fi
  echo -e "  ${GREEN}✓${RESET} docker compose found ($COMPOSE_CMD)"
}

install_attack_deps() {
  echo -e "\n${BOLD}[*] Installing attack script dependencies...${RESET}"
  pip3 install requests lxml PyJWT cryptography beautifulsoup4 \
    --quiet --break-system-packages 2>/dev/null || \
  pip3 install requests lxml PyJWT cryptography beautifulsoup4 \
    --quiet 2>/dev/null || true
  echo -e "  ${GREEN}✓${RESET} Python packages installed"
}

build_and_start() {
  echo -e "\n${BOLD}[*] Building Docker images (first run takes ~2-3 minutes)...${RESET}"
  $COMPOSE_CMD build --quiet

  echo -e "\n${BOLD}[*] Starting all lab services...${RESET}"
  $COMPOSE_CMD up -d

  echo -e "\n${BOLD}[*] Waiting for services to be healthy...${RESET}"
  local max=30
  for i in $(seq 1 $max); do
    saml_ok=0; oauth_ok=0
    curl -sf http://localhost:8080/health >/dev/null 2>&1 && saml_ok=1
    curl -sf http://localhost:4000/health >/dev/null 2>&1 && oauth_ok=1

    if [ $saml_ok -eq 1 ] && [ $oauth_ok -eq 1 ]; then
      echo -e "  ${GREEN}✓${RESET} All services healthy"
      break
    fi
    echo -n "  [$i/$max] Waiting..."
    sleep 3
    echo -e "\r\033[K"
  done
}

print_labs() {
  echo -e "\n${BOLD}${GREEN}Lab services are running!${RESET}\n"
  echo -e "${BOLD}Service URLs:${RESET}"
  echo -e "  ${CYAN}SAML IdP${RESET}           http://localhost:8080"
  echo -e "  ${CYAN}SAML SP (Labs 1-3)${RESET} http://localhost:3000"
  echo -e "  ${CYAN}OAuth Server${RESET}        http://localhost:4000"
  echo -e "  ${CYAN}OAuth Client (Labs 4-7)${RESET} http://localhost:5000"

  echo -e "\n${BOLD}Lab Challenges:${RESET}"
  printf "  %-45s %s\n" "Lab 1 — SAML XSW Attack"           "http://localhost:3000/lab1/login"
  printf "  %-45s %s\n" "Lab 2 — SAML Signature Bypass"     "http://localhost:3000/lab2/login"
  printf "  %-45s %s\n" "Lab 3 — SAML Replay Attack"        "http://localhost:3000/lab3/login"
  printf "  %-45s %s\n" "Lab 4 — OAuth CSRF (No State)"     "http://localhost:5000/lab4/login"
  printf "  %-45s %s\n" "Lab 5 — OAuth Open redirect_uri"   "http://localhost:5000/lab5/login"
  printf "  %-45s %s\n" "Lab 6 — JWT alg:none Attack"       "http://localhost:5000/lab6/login"
  printf "  %-45s %s\n" "Lab 7 — SSO Email Trust ATO"       "http://localhost:5000/lab7/login"

  echo -e "\n${BOLD}Test Credentials:${RESET}"
  printf "  %-35s %s\n" "alice@lab.local / alice123"   "(admin)"
  printf "  %-35s %s\n" "bob@lab.local / bob123"       "(user)"
  printf "  %-35s %s\n" "victim@lab.local / victim123" "(user)"
  printf "  %-35s %s\n" "hacker@attacker.com / hack123" "(user, unverified)"

  echo -e "\n${BOLD}Attack Scripts:${RESET}"
  printf "  %-45s\n" "python3 attacks/lab1_xsw.py"
  printf "  %-45s\n" "python3 attacks/lab2_sig_bypass.py"
  printf "  %-45s\n" "python3 attacks/lab3_replay.py"
  printf "  %-45s\n" "python3 attacks/lab4_oauth_csrf.py"
  printf "  %-45s\n" "python3 attacks/lab5_redirect_uri.py"
  printf "  %-45s\n" "python3 attacks/lab6_jwt_none.py"
  printf "  %-45s\n" "python3 attacks/lab7_account_takeover.py"

  echo -e "\n${BOLD}Useful endpoints:${RESET}"
  echo "  IdP Metadata:  http://localhost:8080/saml/metadata"
  echo "  IdP Cert:      http://localhost:8080/saml/cert"
  echo "  OIDC Discovery:http://localhost:4000/.well-known/openid-configuration"
  echo "  JWKS:          http://localhost:4000/oauth/jwks"
}

run_all_attacks() {
  echo -e "\n${BOLD}${YELLOW}[*] Running all automated attack scripts...${RESET}\n"
  for f in attacks/lab*.py; do
    echo -e "${CYAN}--- Running $f ---${RESET}"
    python3 "$f" 2>/dev/null || true
    echo ""
  done
}

stop_lab() {
  echo -e "${BOLD}[*] Stopping lab...${RESET}"
  $COMPOSE_CMD down
  echo -e "${GREEN}✓ Lab stopped${RESET}"
}

logs() {
  $COMPOSE_CMD logs -f "$@"
}

usage() {
  echo "Usage: $0 [start|stop|restart|attack|logs|status]"
  echo ""
  echo "  start   — Build and start all lab services (default)"
  echo "  stop    — Stop all services"
  echo "  restart — Restart all services"
  echo "  attack  — Run all attack scripts automatically"
  echo "  logs    — Follow container logs"
  echo "  status  — Show container status"
  echo "  clean   — Remove all containers and images"
}

case "${1:-start}" in
  start)
    banner
    check_deps
    install_attack_deps
    build_and_start
    print_labs
    ;;
  stop)
    stop_lab
    ;;
  restart)
    $COMPOSE_CMD restart
    ;;
  attack)
    run_all_attacks
    ;;
  logs)
    shift; logs "$@"
    ;;
  status)
    $COMPOSE_CMD ps
    ;;
  clean)
    $COMPOSE_CMD down --rmi all --volumes --remove-orphans
    echo -e "${GREEN}✓ Cleaned up${RESET}"
    ;;
  help|--help|-h)
    usage
    ;;
  *)
    usage
    exit 1
    ;;
esac
