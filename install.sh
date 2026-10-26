#!/usr/bin/env bash
set -Eeuo pipefail

APP_NAME="dz-route-analyzer"
APP_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_FILE="/etc/systemd/system/${APP_NAME}.service"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run this installer as root: sudo bash install.sh" >&2
  exit 1
fi

if [[ ! -f "${APP_DIR}/requirements.txt" || ! -f "${APP_DIR}/app/main.py" ]]; then
  echo "Run this script from the project directory; required files are missing." >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
  python3 python3-venv python3-pip iputils-ping traceroute iproute2 ca-certificates

if ! id "${APP_NAME}" >/dev/null 2>&1; then
  useradd --system --home-dir "${APP_DIR}" --shell /usr/sbin/nologin "${APP_NAME}"
fi

install -d -o "${APP_NAME}" -g "${APP_NAME}" "${APP_DIR}/data"
if [[ ! -f "${APP_DIR}/.env" ]]; then
  install -m 0640 -o root -g "${APP_NAME}" "${APP_DIR}/.env.example" "${APP_DIR}/.env"
fi

python3 -m venv "${APP_DIR}/.venv"
"${APP_DIR}/.venv/bin/python" -m pip install --upgrade pip
"${APP_DIR}/.venv/bin/pip" install -r "${APP_DIR}/requirements.txt"

chown -R "${APP_NAME}:${APP_NAME}" "${APP_DIR}/.venv" "${APP_DIR}/data"
chown root:"${APP_NAME}" "${APP_DIR}"
chmod 0750 "${APP_DIR}"
chmod 0640 "${APP_DIR}/.env"

# Render the unit with the actual clone directory, rather than assuming /opt.
sed "s|/opt/dz-route-analyzer|${APP_DIR}|g" "${APP_DIR}/dz-route-analyzer.service" > "${SERVICE_FILE}"
chmod 0644 "${SERVICE_FILE}"
systemctl daemon-reload
systemctl enable --now "${APP_NAME}.service"

echo
echo "Installation completed."
echo "Service: systemctl status ${APP_NAME}"
echo "Logs:    journalctl -u ${APP_NAME} -f"
echo "Dashboard: check WEB_PORT in ${APP_DIR}/.env"
