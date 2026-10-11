#!/usr/bin/env bash
# Run the full validation inside a DISPOSABLE VM over SSH and fetch the results back.
#   scripts/run_in_vm.sh user@192.168.122.50
# Create the VM with GNOME Boxes or virt-manager (Fedora Server or Ubuntu Server 24.04), enable SSH, snapshot it.
set -euo pipefail
TARGET="${1:?usage: run_in_vm.sh user@vm-address}"
cd "$(dirname "$0")/.."
echo ">> syncing repo to $TARGET"
rsync -az --delete --exclude '.git' --exclude '.venv' --exclude 'node_modules' --exclude 'frontend' \
      --exclude 'build' --exclude 'results' ./ "$TARGET:povishield/"
echo ">> running validation on the VM (needs sudo there)"
ssh -t "$TARGET" 'cd povishield && make deps && make && make test && make fuzz \
  && sudo make test-root | tee /tmp/test-root.txt ; \
  sudo bash tests/escape/make_rootfs.sh >/dev/null 2>&1 || true; \
  sudo env PS_ROOTFS=/tmp/ps-escape-rootfs python3 tests/escape/run_escape.py 2>&1 | tee /tmp/escape-matrix.txt'
mkdir -p results/vm
scp "$TARGET:/tmp/test-root.txt" "$TARGET:/tmp/escape-matrix.txt" results/vm/ || true
echo ">> VM results saved in results/vm/ (compare with your host: diff results/vm/escape-matrix.txt docs/escape-matrix.txt)"
