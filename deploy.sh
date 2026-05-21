#!/usr/bin/env bash
# =============================================================================
# Deploy digital-signature-service image to OVH VPS
#
# Usage:
#   ./deploy.sh
#
# Pulls the published image from Docker Hub on the VPS and restarts the
# container via docker compose. Preferred path now that CI publishes to
# fikua/digital-signature-service on every main/tag push.
# =============================================================================
set -euo pipefail

IMAGE_NAME="fikua/digital-signature-service"
IMAGE_TAG="${TAG:-latest}"
IMAGE_FULL="${IMAGE_NAME}:${IMAGE_TAG}"

# VPS connection (matches dev-tools/ovh convention)
VPS_IP="51.38.179.236"
VPS_USER="ubuntu"
SSH_KEY="${SSH_KEY:-$(cd "$(dirname "$0")/../eudistack-platform-dev/dev-tools/ovh/ssh" 2>/dev/null && pwd)/id_ed25519}"
SSH_PORT="49222"
SSH_OPTS="-i ${SSH_KEY} -o StrictHostKeyChecking=no -p ${SSH_PORT}"

echo "==> Pulling ${IMAGE_FULL} on VPS (${VPS_IP})"
ssh ${SSH_OPTS} "${VPS_USER}@${VPS_IP}" "sudo docker pull ${IMAGE_FULL}"

echo "==> Restarting mock-qtsp container"
ssh ${SSH_OPTS} "${VPS_USER}@${VPS_IP}" "cd /opt/vps/eudistack && sudo docker compose --env-file .env -f compose.yaml up -d mock-qtsp"

echo "==> Done. Deployed ${IMAGE_FULL}"
echo "==> URL: https://mock-qtsp.altia.fikua.com"
