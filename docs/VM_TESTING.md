# Validating in a disposable VM

The escape and privileged tests mount filesystems, create namespaces and write cgroups. Run them in a VM you can
discard, not on your daily system.

1. Create a VM (GNOME Boxes or virt-manager). Ubuntu Server 24.04 gives useful cross-distro coverage; Fedora Server also works.
2. Enable SSH, create a user with sudo, and take a snapshot.
3. From the repo: `scripts/run_in_vm.sh user@VM-ADDRESS`
4. Results land in `results/vm/` (`test-root.txt`, `escape-matrix.txt`). Compare with the host:
   `diff results/vm/escape-matrix.txt docs/escape-matrix.txt`
5. Revert the snapshot afterwards.

Record the VM's distro, kernel and cgroup version next to any numbers you publish.
