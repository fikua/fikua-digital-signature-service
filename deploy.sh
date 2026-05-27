#!/usr/bin/env bash
# Pull the published image on the Fikua VPS and restart the dss service.
#
# Usage:
#   ./deploy.sh             # deploys :latest
#   TAG=0.3.0 ./deploy.sh   # specific version
#
# Image source: fikua/fikua-digital-signature-service on Docker Hub
# (published by .github/workflows/release.yml on push to main / vX.Y.Z tags).
#
# SSH goes through Cloudflare Tunnel (see ~/.ssh/config for vps.fikua.com).

set -euo pipefail

IMAGE="fikua/fikua-digital-signature-service:${TAG:-latest}"
SSH_HOST="vps.fikua.com"
REMOTE_DIR="/opt/vps/projects/fikua-lab/dss"

echo "==> Pulling ${IMAGE} on ${SSH_HOST}"
ssh "${SSH_HOST}" "sudo docker pull ${IMAGE}"

echo "==> Restarting dss"
ssh "${SSH_HOST}" "cd ${REMOTE_DIR} && sudo docker compose --env-file .env up -d"

echo "==> Done. URL: https://dss.fikua.com"
