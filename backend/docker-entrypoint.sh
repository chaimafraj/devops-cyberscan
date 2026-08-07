#!/bin/sh
set -e

# Bind mounts (./backend/media) often hide the image directories and may be
# root-owned. Ensure the PDF output path exists and is writable before drop.
mkdir -p /app/media/rapports /app/staticfiles

if [ "$(id -u)" = "0" ]; then
  chown -R cyberscan:cyberscan /app/media /app/staticfiles 2>/dev/null || true
  exec runuser -u cyberscan -- "$@"
fi

exec "$@"
