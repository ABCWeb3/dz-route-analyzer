#!/usr/bin/env bash
set -Eeuo pipefail

APP_NAME="dz-route-analyzer"
APP_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_FILE="/etc/systemd/system/${APP_NAME}.service"

LOG_FILE="/var/log/dz-route-analyzer-install.log"
RESET=$'\033[0m'
CYAN=$'\033[36m'
GREEN=$'\033[32m'
RED=$'\033[31m'
BOLD=$'\033[1m'
: > "$LOG_FILE"
progress() {
  local percent="$1" message="$2" width=24 filled bar empty
  filled=$((percent * width / 100))
  bar=$(printf '%*s' "$filled" '' | tr ' ' '█')
  empty=$(printf '%*s' "$((width-filled))" '' | tr ' ' '░')
  printf "\r%s[%s%s] %3d%%\033[0m %s\033[K\n" "$CYAN$BOLD" "$bar" "$empty" "$percent" "$message"
}
run_step() {
  local percent="$1" message="$2"
  shift 2
  progress "$percent" "$message"
  if "$@" >>"$LOG_FILE" 2>&1; then return 0; fi
  printf "\n%sInstallation failed: %s\033[0m\n" "$RED$BOLD" "$message" >&2
  tail -n 25 "$LOG_FILE" >&2 || true
  exit 1
}

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run this installer as root: sudo bash install.sh" >&2
  exit 1
fi

if [[ ! -f "${APP_DIR}/requirements.txt" || ! -f "${APP_DIR}/app/main.py" ]]; then
  echo "Run this script from the project directory; required files are missing." >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
run_step 8 "Preparing package lists" apt-get update
run_step 22 "Installing runtime and network tools" apt-get install -y --no-install-recommends \
  python3 python3-venv python3-pip iputils-ping traceroute iproute2 ca-certificates

if ! id "${APP_NAME}" >/dev/null 2>&1; then
  useradd --system --home-dir "${APP_DIR}" --shell /usr/sbin/nologin "${APP_NAME}"
fi

install -d -o "${APP_NAME}" -g "${APP_NAME}" "${APP_DIR}/data"
if [[ ! -f "${APP_DIR}/.env" ]]; then
  install -m 0640 -o root -g "${APP_NAME}" "${APP_DIR}/.env.example" "${APP_DIR}/.env"
fi

run_step 52 "Creating Python virtual environment" python3 -m venv "${APP_DIR}/.venv"
run_step 60 "Updating pip package manager" "${APP_DIR}/.venv/bin/python" -m pip install --upgrade pip
run_step 68 "Installing Python dependencies" "${APP_DIR}/.venv/bin/pip" install -r "${APP_DIR}/requirements.txt"

chown -R "${APP_NAME}:${APP_NAME}" "${APP_DIR}/.venv" "${APP_DIR}/data"
chown root:"${APP_NAME}" "${APP_DIR}"
chmod 0750 "${APP_DIR}"
chmod 0640 "${APP_DIR}/.env"

# Render the unit with the actual clone directory, rather than assuming /opt.
sed "s|/opt/dz-route-analyzer|${APP_DIR}|g" "${APP_DIR}/dz-route-analyzer.service" > "${SERVICE_FILE}"
chmod 0644 "${SERVICE_FILE}"
run_step 96 "Reloading service manager" systemctl daemon-reload
run_step 98 "Starting dashboard and monitoring" systemctl enable --now "${APP_NAME}.service"

echo
progress 100 "Installation completed successfully"
printf "\033[32;1m✓ Dashboard service is ready\033[0m\n"
echo "Service: systemctl status ${APP_NAME}"
echo "Logs:    journalctl -u ${APP_NAME} -f"
echo "Dashboard: check WEB_PORT in ${APP_DIR}/.env"
