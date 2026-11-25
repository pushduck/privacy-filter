#!/usr/bin/env bash
# 交叉编译全部平台的可执行文件并打包到 dist/。Makefile 与 GitHub Actions 共用。
# 用法：scripts/dist.sh [版本号]      例：scripts/dist.sh v1.2.0
# 可用 PLATFORMS 环境变量覆盖目标平台，例：PLATFORMS="linux/amd64 darwin/arm64"
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${1:-$(git -C "$ROOT" describe --tags --always --dirty 2>/dev/null || echo dev)}"
PLATFORMS="${PLATFORMS:-linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64}"
# 命令目录 → 产物名
CMDS="gateway:pf-gateway server:pf-server http:pf-http grpc:pf-grpc"
DIST="$ROOT/dist"

rm -rf "$DIST" && mkdir -p "$DIST"
cd "$ROOT"

for p in $PLATFORMS; do
  os="${p%/*}"; arch="${p#*/}"
  name="privacy-filter_${VERSION}_${os}_${arch}"
  out="$DIST/$name"
  mkdir -p "$out/rules"
  ext=""; [ "$os" = windows ] && ext=".exe"
  for c in $CMDS; do
    dir="${c%%:*}"; bin="${c#*:}"
    echo ">> $os/$arch  $bin$ext"
    CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath \
      -ldflags "-s -w -X main.version=$VERSION" -o "$out/$bin$ext" "./cmd/$dir"
  done
  cp rules/gitleaks.toml "$out/rules/"
  cp LICENSE README.md README.zh-CN.md "$out/"
  if [ "$os" = windows ]; then
    (cd "$DIST" && zip -qr "$name.zip" "$name")
  else
    tar -C "$DIST" -czf "$DIST/$name.tar.gz" "$name"
  fi
  rm -rf "$out"
done

(cd "$DIST" && { command -v sha256sum >/dev/null && sha256sum ./*.tar.gz ./*.zip || shasum -a 256 ./*.tar.gz ./*.zip; } | sed 's# \./# #' > checksums.txt)
echo "完成：$DIST"
ls -lh "$DIST"
