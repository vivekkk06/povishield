"""Union several profiles (multiple learning runs always beat a single run)."""
import sys
from .common import load_profile, save_profile


def merge_profiles(sets):
    out = set()
    for s in sets:
        out |= s
    return out


if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit("usage: python3 -m analysis.merge OUT.json IN1.json [IN2.json ...]")
    save_profile(sys.argv[1], merge_profiles(load_profile(p) for p in sys.argv[2:]))
