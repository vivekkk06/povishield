#!/usr/bin/env bash
set -eu
cd "$(dirname "$0")/../.."
R="${PS_ROOTFS:-/tmp/ps-escape-rootfs}"
mkdir -p build/escape-static "$R"/{t,tmp,proc,dev}
for src in tests/escape/*.c; do
  gcc -O0 -Wall -static "$src" -o "build/escape-static/$(basename "${src%.c}")"
done
cp build/escape-static/* "$R/t/"
echo HOST-ONLY > /tmp/ps-host-marker
echo "rootfs ready: $R"
