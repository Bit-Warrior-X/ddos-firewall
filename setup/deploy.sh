#!/bin/bash
# deploy_auto.sh - Automated deployment with password + token provisioning (with remote uninstall step)
set -euo pipefail

REMOTE_SERVER="root@192.142.44.140"      # Change this
REMOTE_PASSWORD="EaD7dvi8DmVtwAWG9oKE"   # Change this
REMOTE_PATH="/tmp/setup.sh"

TOKEN=""

usage() {
  cat <<EOF
Usage: $0 --token=YOUR_TOKEN_HERE

Description:
  0) Runs /tmp/uninstall.sh on the remote host if present (non-interactive)
  1) Copies setup.sh to the remote server
  2) Runs setup.sh on the remote server
  2.5) Provisions /usr/local/share/ebpf_firewall/token securely
  3) Starts the api_parser service

Options:
  --token=VALUE    Required. Token to write on the remote host.
EOF
}

# --- Parse args ---
for arg in "$@"; do
  case "$arg" in
    --token=*)
      TOKEN="${arg#--token=}"
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $arg"
      usage
      exit 1
      ;;
  esac
done

if [[ -z "${TOKEN}" ]]; then
  echo "Error: --token=... is required"
  usage
  exit 1
fi

# --- Ensure sshpass exists ---
if ! command -v sshpass >/dev/null 2>&1; then
  echo "Installing sshpass..."
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update -y && sudo apt-get install -y sshpass
  elif command -v yum >/dev/null 2>&1; then
    sudo yum install -y epel-release || true
    sudo yum install -y sshpass
  else
    echo "Error: Could not install sshpass (no apt-get or yum). Install it manually and re-run."
    exit 1
  fi
fi

echo "Deploying to remote server: ${REMOTE_SERVER}"

# --- Step 0: Run uninstall.sh on remote if present (non-interactive, ignore errors) ---
echo "Step 0: Attempting to run /tmp/uninstall.sh on remote (if present)..."
sshpass -p "$REMOTE_PASSWORD" ssh -o StrictHostKeyChecking=no -t "$REMOTE_SERVER" "
  if [ -f /tmp/uninstall.sh ]; then
    chmod +x /tmp/uninstall.sh || true
    # Run non-interactively with --yes; detach stdin to avoid consuming the sudo password
    printf '%s\n' '$REMOTE_PASSWORD' | sudo -S -- bash -c '/tmp/uninstall.sh --yes --purge-libs --purge-openresty </dev/null' || true
  else
    echo '[INFO] /tmp/uninstall.sh not found on remote. Skipping uninstall.'
  fi
"

# --- Step 1: Copy setup.sh to remote ---
echo "Step 1: Copying setup.sh to remote server..."
sshpass -p "$REMOTE_PASSWORD" scp -o StrictHostKeyChecking=no setup.sh "$REMOTE_SERVER":"$REMOTE_PATH"

# --- Step 2: Run setup.sh on remote (detach stdin so it can't consume password) ---
echo "Step 2: Running setup.sh on remote server..."
sshpass -p "$REMOTE_PASSWORD" ssh -o StrictHostKeyChecking=no -t "$REMOTE_SERVER" "
  chmod +x '$REMOTE_PATH' &&
  printf '%s\n' '$REMOTE_PASSWORD' | sudo -S -- bash -c '$REMOTE_PATH </dev/null'
"

# --- Step 2.5: Provision token file securely on remote (stable method) ---
echo "Step 2.5: Writing token to /usr/local/share/ebpf_firewall/token ..."

# create a secure local temp file with the token
LOCAL_TMP="$(mktemp)"
trap 'rm -f "$LOCAL_TMP"' EXIT
umask 077
printf '%s' "$TOKEN" > "$LOCAL_TMP"

# choose a predictable remote tmp path (we'll remove it after)
REMOTE_TMP="/tmp/ebpf_token_$$"

# copy local tmp to remote tmp (no sudo involved)
sshpass -p "$REMOTE_PASSWORD" scp -o StrictHostKeyChecking=no "$LOCAL_TMP" "$REMOTE_SERVER":"$REMOTE_TMP"

# move it into place using sudo on remote and set secure perms/ownership
sshpass -p "$REMOTE_PASSWORD" ssh -o StrictHostKeyChecking=no -t "$REMOTE_SERVER" "
  printf '%s\n' '$REMOTE_PASSWORD' | sudo -S -- bash -e -c '
    install -d -m 700 /usr/local/share/ebpf_firewall
    install -m 600 -o root -g root \"$REMOTE_TMP\" /usr/local/share/ebpf_firewall/token
    rm -f \"$REMOTE_TMP\"
  '
"

# --- Step 3: Start the api_parser service ---
echo "Step 3: Starting api_parser service..."
sshpass -p "$REMOTE_PASSWORD" ssh -o StrictHostKeyChecking=no -t "$REMOTE_SERVER" "systemctl restart api_parser.service && systemctl status api_parser.service"

# --- Step 4: Start the l7 service ---
echo "Step 4: Starting l7_firewall service..."
sshpass -p "$REMOTE_PASSWORD" ssh -o StrictHostKeyChecking=no -t "$REMOTE_SERVER" "systemctl restart l7_firewall"

# --- Step 5: Start the l4 service ---
echo "Step 5: Starting ebpf_firewall service..."
sshpass -p "$REMOTE_PASSWORD" ssh -o StrictHostKeyChecking=no -t "$REMOTE_SERVER" "systemctl restart ebpf_firewall.service && systemctl status ebpf_firewall.service"

echo "Deployment completed."