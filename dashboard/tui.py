#!/usr/bin/env python3
"""Live view of every povishield-* cgroup (mem, pids, cpu%). Ctrl-C to quit."""
import glob, os, time

CG = "/sys/fs/cgroup"


def rd(p, d="-"):
    try:
        return open(p).read().strip()
    except OSError:
        return d


def cpu_usec(d):
    for line in rd(f"{d}/cpu.stat", "").splitlines():
        if line.startswith("usage_usec"):
            return int(line.split()[1])
    return 0


def main(interval=1.0):
    prev = {}
    while True:
        os.system("clear")
        print(f"PoViShield dashboard  {time.strftime('%H:%M:%S')}\n")
        print(f"{'cgroup':<26}{'mem':>12}{'mem.max':>14}{'pids':>8}{'pids.max':>10}{'cpu%':>8}")
        for d in sorted(glob.glob(f"{CG}/povishield-*")):
            u = cpu_usec(d)
            pct = (u - prev.get(d, u)) / (interval * 1e6) * 100
            prev[d] = u
            mem = rd(f"{d}/memory.current", "0")
            print(f"{os.path.basename(d):<26}{int(mem)/1048576:>10.1f}MB{rd(d + '/memory.max'):>14}"
                  f"{rd(d + '/pids.current'):>8}{rd(d + '/pids.max'):>10}{pct:>8.1f}")
        time.sleep(interval)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
