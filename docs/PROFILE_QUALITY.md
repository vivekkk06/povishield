# Profile quality

A learned profile contains the syscalls **observed** while the program ran. It is evidence about those executions,
not a guarantee about future ones.

## Training vs. held-out workloads
Every target in `evaluation/targets.toml` has `train` commands (learned) and `test` commands (never learned).
Held-out coverage and compatibility are measured on the test commands only.

## What went wrong and what was fixed
| finding | cause | fix |
|---|---|---|
| `ls` killed on `readlink` | training listed directories without symlinks | added a symlink-rich training run (`ls -l /`) |
| `grep` killed on first sandboxed run | trained with stdout on `/dev/null`, where grep skips `write()` | train with stdout piped, as in the test |
| shell pipelines hid kills | exit status of a pipeline is that of its last command | `bash -c 'set -o pipefail; ...'`, stdout comparison, and SIGSYS-as-159 detection |

## Practical guidance
- Learn from several workloads and merge (`python3 -m analysis.merge out.json a.json b.json`).
- Run in `--audit` mode first; it logs violations instead of killing.
- Re-learn when the program, its libraries or its inputs change meaningfully.
- Compare versions with `python3 -m analysis.diff old.json new.json`; new high-weight syscalls are highlighted.
