#!/bin/sh
set -e

REPO="shuakami/arc"
BIN="arc-gateway"
INSTALL_DIR="/usr/local/bin"

# 检测平台
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "${OS}_${ARCH}" in
  linux_x86_64)  ASSET="${BIN}-linux-x86_64" ;;
  linux_aarch64) ASSET="${BIN}-linux-arm64" ;;
  darwin_arm64)  ASSET="${BIN}-macos-arm64" ;;
  *)
    echo "Unsupported platform: ${OS}_${ARCH}"
    exit 1
    ;;
esac

# 获取最新版本
VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
  | grep '"tag_name"' | cut -d'"' -f4)

echo "Installing Arc Gateway ${VERSION}..."

# 下载
URL="https://github.com/${REPO}/releases/download/${VERSION}/${ASSET}"
curl -fsSL "${URL}" -o "/tmp/${BIN}"
curl -fsSL "${URL}.sha256" -o "/tmp/${BIN}.sha256"

# 校验
cd /tmp
sha256sum -c "${BIN}.sha256"

# 安装
chmod +x "/tmp/${BIN}"
sudo mv "/tmp/${BIN}" "${INSTALL_DIR}/${BIN}"

echo "Arc Gateway ${VERSION} installed to ${INSTALL_DIR}/${BIN}"
echo "Run: arc-gateway --help"
