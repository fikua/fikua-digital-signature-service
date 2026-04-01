#!/usr/bin/env bash
# =============================================================================
# Deploy mock-qtsp image to OVH VPS
#
# Usage:
#   ./deploy.sh
#
# Builds the Docker image locally, transfers it to the VPS via SCP,
# loads it, and restarts the container.
# =============================================================================
set -euo pipefail

IMAGE_NAME="eudistack/mock-qtsp"
IMAGE_TAG="${TAG:-latest}"
IMAGE_FULL="${IMAGE_NAME}:${IMAGE_TAG}"
TAR_FILE="mock-qtsp-${IMAGE_TAG}.tar.gz"

# VPS connection (matches dev-tools/ovh convention)
VPS_IP="51.38.179.236"
VPS_USER="ubuntu"
SSH_KEY="${SSH_KEY:-$(cd "$(dirname "$0")/../eudistack-platform-dev/dev-tools/ovh/ssh" 2>/dev/null && pwd)/id_ed25519}"
SSH_PORT="49222"
SSH_OPTS="-i ${SSH_KEY} -o StrictHostKeyChecking=no -p ${SSH_PORT}"
SCP_OPTS="-i ${SSH_KEY} -o StrictHostKeyChecking=no -P ${SSH_PORT}"

echo "==> Building Docker image: ${IMAGE_FULL}"
docker build -t "${IMAGE_FULL}" .

echo "==> Saving image to ${TAR_FILE}"
docker save "${IMAGE_FULL}" | gzip > "${TAR_FILE}"

echo "==> Uploading to VPS (${VPS_IP})"
scp ${SCP_OPTS} "${TAR_FILE}" "${VPS_USER}@${VPS_IP}:/tmp/${TAR_FILE}"

echo "==> Loading image on VPS"
ssh ${SSH_OPTS} "${VPS_USER}@${VPS_IP}" "sudo docker load < /tmp/${TAR_FILE} && rm /tmp/${TAR_FILE}"

echo "==> Restarting mock-qtsp container"
ssh ${SSH_OPTS} "${VPS_USER}@${VPS_IP}" "cd /opt/eudistack && sudo docker compose up -d mock-qtsp"

rm -f "${TAR_FILE}"
echo "==> Done. mock-qtsp deployed as ${IMAGE_FULL}"
echo "==> URL: https://mock-qtsp.altia.fikua.com"
