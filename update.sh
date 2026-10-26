#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
APP_NAME="dz-route-analyzer"

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

echo "Backup saved to: ${BACKUP}"
echo "Updating source from GitHub..."
git -C "${APP_DIR}" pull --ff-only
echo "Installing/updating dependencies..."
bash "${APP_DIR}/install.sh"
systemctl restart "${APP_NAME}.service"
systemctl --no-pager --full status "${APP_NAME}.service"
echo
echo "Update completed. Local .env and measurement database were backed up."
