#!/bin/bash
# deploy_auto.sh - Automated deployment with password + token provisioning (with remote uninstall step)
set -euo pipefail

REMOTE_SERVER="root@192.142.44.140"      # Change this
REMOTE_PASSWORD="EaD7dvi8DmVtwAWG9oKE"   # Change this
REMOTE_PATH="/tmp/setup.sh"

TOKEN=""
RESTORE_CONFIG=false

usage() {
  cat <<EOF
Usage: $0 --token=YOUR_TOKEN_HERE [--restore-config]

Description:
  0) If --restore-config: Saves current configuration to /tmp/config/
  0.5) Runs /tmp/uninstall.sh on the remote host if present (non-interactive)
  1) Copies setup.sh to the remote server
  2) Runs setup.sh on the remote server
  2.5) Provisions /usr/local/share/ebpf_firewall/token securely
  2.7) If --restore-config: Restores saved configuration from /tmp/config/
  3) Starts the api_parser service

Options:
  --token=VALUE       Required. Token to write on the remote host.
  --restore-config    Optional. Save config before deployment and restore after.
EOF
}

# --- Parse args ---
for arg in "$@"; do
  case "$arg" in
    --token=*)
      TOKEN="${arg#--token=}"
      ;;
    --restore-config)
      RESTORE_CONFIG=true
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

# --- Step 0: Save current configuration if --restore-config is enabled ---
if [[ "$RESTORE_CONFIG" == "true" ]]; then
  echo "Step 0: Saving current configuration on remote server..."
  
  # Copy save_config.sh script to remote
  sshpass -p "$REMOTE_PASSWORD" scp -o StrictHostKeyChecking=no payload/save_config.sh "$REMOTE_SERVER":/tmp/save_config.sh
  
  # Run save_config.sh on remote to backup current configuration
  sshpass -p "$REMOTE_PASSWORD" ssh -o StrictHostKeyChecking=no -t "$REMOTE_SERVER" "
    export DEBIAN_FRONTEND=noninteractive
    export NEEDRESTART_MODE=a
    chmod +x /tmp/save_config.sh &&
    printf '%s\n' '$REMOTE_PASSWORD' | sudo -S -- bash -c '/tmp/save_config.sh </dev/null' || echo '[WARNING] save_config.sh failed or no config to save'
  "
  
  echo "Configuration saved to /tmp/config/ on remote server"
fi

# --- Step 0.5: Run uninstall.sh on remote if present (non-interactive, ignore errors) ---
echo "Step 0.5: Attempting to run /tmp/uninstall.sh on remote (if present)..."
sshpass -p "$REMOTE_PASSWORD" ssh -o StrictHostKeyChecking=no -t "$REMOTE_SERVER" "
  export DEBIAN_FRONTEND=noninteractive
  export NEEDRESTART_MODE=a
  if [ -f /tmp/uninstall.sh ]; then
    chmod +x /tmp/uninstall.sh || true
    # Run non-interactively with --yes; detach stdin to avoid consuming the sudo password
    printf '%s\n' '$REMOTE_PASSWORD' | sudo -S -- bash -c 'DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a /tmp/uninstall.sh --yes --purge-libs --purge-openresty </dev/null' || true
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
  export DEBIAN_FRONTEND=noninteractive
  export NEEDRESTART_MODE=a
  chmod +x '$REMOTE_PATH' &&
  printf '%s\n' '$REMOTE_PASSWORD' | sudo -S -- bash -c 'DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a $REMOTE_PATH </dev/null'
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
  export DEBIAN_FRONTEND=noninteractive
  export NEEDRESTART_MODE=a
  printf '%s\n' '$REMOTE_PASSWORD' | sudo -S -- bash -e -c '
    install -d -m 700 /usr/local/share/ebpf_firewall
    install -m 600 -o root -g root \"$REMOTE_TMP\" /usr/local/share/ebpf_firewall/token
    rm -f \"$REMOTE_TMP\"
  '
"

# --- Step 2.7: Restore configuration if --restore-config is enabled ---
if [[ "$RESTORE_CONFIG" == "true" ]]; then
  echo "Step 2.7: Restoring saved configuration on remote server..."
  
  # Copy restore_config.sh script to remote
  sshpass -p "$REMOTE_PASSWORD" scp -o StrictHostKeyChecking=no payload/restore_config.sh "$REMOTE_SERVER":/tmp/restore_config.sh
  
  # Run restore_config.sh on remote to restore backed up configuration
  sshpass -p "$REMOTE_PASSWORD" ssh -o StrictHostKeyChecking=no -t "$REMOTE_SERVER" "
    export DEBIAN_FRONTEND=noninteractive
    export NEEDRESTART_MODE=a
    chmod +x /tmp/restore_config.sh &&
    printf '%s\n' '$REMOTE_PASSWORD' | sudo -S -- bash -c '/tmp/restore_config.sh </dev/null' || echo '[WARNING] restore_config.sh failed'
  "
  
  echo "Configuration restored from /tmp/config/ on remote server"
fi

# --- Step 3: Start the api_parser service ---
echo "Step 3: Starting api_parser service..."
sshpass -p "$REMOTE_PASSWORD" ssh -o StrictHostKeyChecking=no -t "$REMOTE_SERVER" "
  export DEBIAN_FRONTEND=noninteractive
  export NEEDRESTART_MODE=a
  systemctl restart api_parser.service && systemctl status api_parser.service
"

# --- Step 4: Start the l7 service ---
#echo "Step 4: Starting l7_firewall service..."
#sshpass -p "$REMOTE_PASSWORD" ssh -o StrictHostKeyChecking=no -t "$REMOTE_SERVER" "systemctl restart l7_firewall"

# --- Step 5: Start the l4 service ---
#echo "Step 5: Starting ebpf_firewall service..."
#sshpass -p "$REMOTE_PASSWORD" ssh -o StrictHostKeyChecking=no -t "$REMOTE_SERVER" "systemctl restart ebpf_firewall.service && systemctl status ebpf_firewall.service"

echo "Deployment completed."