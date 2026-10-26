#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
APP_NAME="dz-route-analyzer"
CYAN='\033[36m'
GREEN='\033[32m'
BOLD='\033[1m'
progress() {
  printf "\r%s[%3d%%] %s\033[0m\n" "$CYAN$BOLD" "$1" "$2"
}

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo bash update.sh" >&2
  exit 1
fi
if [[ ! -d "${APP_DIR}/.git" ]]; then
  echo "This directory is not a Git clone: ${APP_DIR}" >&2
  exit 1
fi

STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP="/root/${APP_NAME}-backup-${STAMP}"
mkdir -p "${BACKUP}"
[[ ! -f "${APP_DIR}/.env" ]] || cp -a "${APP_DIR}/.env" "${BACKUP}/.env"
[[ ! -d "${APP_DIR}/data" ]] || cp -a "${APP_DIR}/data" "${BACKUP}/data"

progress 10 "Backing up configuration and history"
echo "Backup saved to: ${BACKUP}"
progress 25 "Downloading the latest version"
git -C "${APP_DIR}" pull --ff-only
progress 40 "Installing dependencies and preparing dashboard"
bash "${APP_DIR}/install.sh"
progress 90 "Restarting monitoring service"
systemctl restart "${APP_NAME}.service"
if systemctl is-active --quiet "${APP_NAME}.service"; then
  progress 100 "Update completed successfully"
  printf "%s✓ Dashboard is running%s\n" "$GREEN$BOLD" '\033[0m'
else
  echo "Update finished but the service is not active. Check: journalctl -u ${APP_NAME} -n 80 --no-pager" >&2
  exit 1
fi
