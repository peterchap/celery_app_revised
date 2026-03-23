import os
import sys
import argparse

def main():
    parser = argparse.ArgumentParser(description="Grow LMDB mapsize for DNS cache")
    parser.add_argument("path", help="LMDB directory path (e.g., /var/lib/lmdb/dns)")
    parser.add_argument("--sizeGB", type=int, default=20, help="Target mapsize in GB (default: 20)")
    args = parser.parse_args()

    # Lazy import to ensure package resolution
    try:
        from dns_module import dns_lookup
    except ImportError:
        # Try adding project root to sys.path
        here = os.path.dirname(os.path.dirname(__file__))
        if here not in sys.path:
            sys.path.insert(0, here)
        from dns_module import dns_lookup

    target_size = int(args.sizeGB) * 1024 * 1024 * 1024
    env = dns_lookup.init_lmdb(args.path, readonly=False, lock=True)
    try:
        info_before = env.info()
        cur = int(info_before.get("map_size", 0)) if isinstance(info_before, dict) else 0
        env.set_mapsize(target_size)
        info_after = env.info()
        new = int(info_after.get("map_size", 0)) if isinstance(info_after, dict) else target_size
        print(f"LMDB mapsize changed: {cur} -> {new}")
    except Exception as e:
        print(f"Failed to adjust mapsize: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
