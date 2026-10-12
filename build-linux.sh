#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GO="${GO_TOOL:-/usr/local/go/bin/go}"

echo "==> Cleaning old binaries..."
rm -f "${SCRIPT_DIR}/build-linux/usque"

echo "==> Building Linux static binary..."
mkdir -p "${SCRIPT_DIR}/build-linux"
cd "${SCRIPT_DIR}"
CGO_ENABLED=0 "${GO}" build -ldflags="-s -w" -v -o build-linux/usque .

echo "==> Done."
echo "Linux : ${SCRIPT_DIR}/build-linux/usque"
echo "Windows: ${SCRIPT_DIR}/build-win/usque.exe"
