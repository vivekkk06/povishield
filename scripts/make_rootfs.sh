#!/usr/bin/env bash
# Builds a minimal busybox rootfs at ./rootfs for:  sudo build/povishield run --rootfs ./rootfs -- /bin/sh
set -euo pipefail
R="${1:-rootfs}"
mkdir -p "$R"/{bin,proc,dev,tmp,etc}
cp "$(command -v busybox)" "$R/bin/busybox"       # needs: apt install busybox-static
for a in sh ls cat echo ps id sleep mount; do ln -sf busybox "$R/bin/$a"; done
echo "rootfs ready at $R"
