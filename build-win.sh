#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GO="${GO_TOOL:-/usr/local/go/bin/go}"

echo "==> Cleaning old binaries..."
rm -f "${SCRIPT_DIR}/build-win/usque.exe"

echo "==> Building Windows static binary (cross-compile)..."
mkdir -p "${SCRIPT_DIR}/build-win"
cd "${SCRIPT_DIR}"
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 "${GO}" build -v -o build-win/usque.exe .

echo "==> Done."
echo "Linux : ${SCRIPT_DIR}/build-linux/usque"
echo "Windows: ${SCRIPT_DIR}/build-win/usque.exe"
