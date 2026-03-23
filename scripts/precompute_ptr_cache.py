import asyncio
import argparse
import os
import ipaddress
from typing import List

# Ensure local module imports
from dns_module import dns_lookup

async def precompute_ptr_cache(input_path: str, map_path: str, nameservers: List[str], workers: int) -> None:
    # Initialize LMDB (write mode) and resolver
    # Initialize dedicated PTR LMDB
    dns_lookup.init_lmdb_ptr(map_path, readonly=False, lock=True)
    resolver = dns_lookup.get_default_resolver(nameservers=nameservers)
    sem = dns_lookup.default_semaphore(limit=max(workers, 1))

    async def process_ip(ip: str):
        ip = ip.strip()
        if not ip:
            return
        try:
            rev = ipaddress.ip_address(ip).reverse_pointer
        except Exception:
            return
        try:
            # Resolve PTR without writing via writer queue
            rcode, answers, ttl = await dns_lookup.lookup_ptr(rev, resolver=resolver, semaphore=sem, use_lmdb=False)
            key = f"PTR:{rev}".encode('utf-8')
            val = dns_lookup._serialize_value(rcode, answers or [], ttl or 0)
            env = dns_lookup._lmdb_env_ptr
            if env and rcode is not None:
                try:
                    with env.begin(write=True) as txn:
                        txn.put(key, val)
                except Exception:
                    pass
        except Exception:
            pass

    async def run():
        # Read IPs and process with bounded concurrency
        sem_local = asyncio.Semaphore(workers)
        tasks = []
        with open(input_path, 'r', encoding='utf-8') as f:
            for line in f:
                ip = line.strip()
                if not ip:
                    continue
                async def _wrapped(ip=ip):
                    async with sem_local:
                        await process_ip(ip)
                tasks.append(asyncio.create_task(_wrapped()))
                # Avoid overwhelming memory: flush in chunks
                if len(tasks) >= workers * 50:
                    await asyncio.gather(*tasks)
                    tasks.clear()
        if tasks:
            await asyncio.gather(*tasks)

    await run()

    # Graceful shutdown of resolver/semaphore; keep PTR LMDB open for reuse
    try:
        await dns_lookup.shutdown()
    except Exception:
        pass

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Precompute PTR cache from IP list')
    parser.add_argument('--input', required=True, help='Path to file with IPs (one per line)')
    parser.add_argument('--mapdir', required=True, help='PTR LMDB directory')
    parser.add_argument('--nameservers', default='127.0.0.1', help='Comma-separated nameservers (default: 127.0.0.1)')
    parser.add_argument('--workers', type=int, default=400, help='Concurrent workers (default: 400)')
    args = parser.parse_args()

    ns = [s.strip() for s in (args.nameservers or '127.0.0.1').split(',') if s.strip()]

    # Optional mapsize override via env
    if not os.getenv('DNS_LMDB_PTR_MAPSIZE_GB'):
        os.environ['DNS_LMDB_PTR_MAPSIZE_GB'] = '50'  # default large mapsize; adjust as needed

    asyncio.run(precompute_ptr_cache(args.input, args.mapdir, ns, args.workers))
