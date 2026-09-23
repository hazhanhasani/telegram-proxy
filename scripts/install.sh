#!/usr/bin/env bash
set -euo pipefail
if [ "$(id -u)" -ne 0 ]; then echo "Run as root: sudo bash scripts/install.sh"; exit 1; fi
if ! command -v apt-get >/dev/null 2>&1; then echo "Automatic installer currently supports Debian/Ubuntu."; exit 2; fi
export DEBIAN_FRONTEND=noninteractive
if ! command -v openssl >/dev/null 2>&1; then apt-get update -y; apt-get install -y openssl; fi
if ! command -v docker >/dev/null 2>&1; then apt-get update -y; apt-get install -y docker.io docker-compose-plugin; systemctl enable --now docker; fi
if ! docker compose version >/dev/null 2>&1; then echo "Docker Compose plugin is required."; exit 3; fi
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; cd "$ROOT_DIR"
if [ ! -f .env ]; then
  read -r -p "Admin email: " ADMIN_EMAIL
  read -r -s -p "Admin password: " ADMIN_PASSWORD; echo
  if [ "${#ADMIN_PASSWORD}" -lt 12 ]; then echo "Admin password must be at least 12 characters."; exit 4; fi
  SECRET_KEY="$(openssl rand -hex 48)"; DB_PASSWORD="$(openssl rand -hex 32)"
  cat >.env <<EOF
APP_NAME=Telegram Proxy Control
APP_ENV=production
PANEL_PORT=8080
PUBLIC_BASE_URL=http://$(hostname -I | awk '{print $1}'):8080
SECRET_KEY=$SECRET_KEY
ENCRYPTION_KEY=
SESSION_HTTPS_ONLY=false
ADMIN_EMAIL=$ADMIN_EMAIL
ADMIN_PASSWORD=$ADMIN_PASSWORD
DB_PASSWORD=$DB_PASSWORD
DATABASE_URL=postgresql+psycopg://telegram:$DB_PASSWORD@db:5432/telegram_proxy
SSH_TIMEOUT=20
SSH_CONNECT_TIMEOUT=12
HEALTH_INTERVAL=60
API_TOKEN=
EOF
  chmod 600 .env
else echo ".env exists; keeping it."; fi
mkdir -p data
docker compose up -d --build
echo "Panel: http://$(hostname -I | awk '{print $1}'):8080"
echo "Production: put it behind HTTPS and set SESSION_HTTPS_ONLY=true."
