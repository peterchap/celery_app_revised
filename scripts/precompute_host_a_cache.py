import asyncio
import argparse
import os
from typing import List

from dns_module import dns_lookup

async def precompute_host_a_cache(input_path: str, map_path: str, nameservers: List[str], workers: int) -> None:
    dns_lookup.init_lmdb(map_path, readonly=False, lock=True)
    resolver = dns_lookup.get_default_resolver(nameservers=nameservers)
    sem = dns_lookup.default_semaphore(limit=max(workers, 1))

    async def process_host(host: str):
        host = host.strip().rstrip('.')
        if not host:
            return
        try:
            rcode, answers, ttl = await dns_lookup.lookup_a(host, resolver=resolver, semaphore=sem, use_lmdb=True)
        except Exception:
            return

    async def run():
        sem_local = asyncio.Semaphore(workers)
        tasks = []
        with open(input_path, 'r', encoding='utf-8') as f:
            for line in f:
                host = line.strip()
                if not host:
                    continue
                async def _wrapped(h=host):
                    async with sem_local:
                        await process_host(h)
                tasks.append(asyncio.create_task(_wrapped()))
                if len(tasks) >= workers * 50:
                    await asyncio.gather(*tasks)
                    tasks.clear()
        if tasks:
            await asyncio.gather(*tasks)

    await run()
    await dns_lookup.shutdown()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Precompute A cache for hostnames')
    parser.add_argument('--input', required=True, help='Path to file with hostnames (one per line)')
    parser.add_argument('--mapdir', required=True, help='Default LMDB directory')
    parser.add_argument('--nameservers', default='127.0.0.1', help='Comma-separated nameservers (default: 127.0.0.1)')
    parser.add_argument('--workers', type=int, default=400, help='Concurrent workers (default: 400)')
    args = parser.parse_args()

    ns = [s.strip() for s in (args.nameservers or '127.0.0.1').split(',') if s.strip()]

    if not os.getenv('DNS_LMDB_MAPSIZE_GB'):
        os.environ['DNS_LMDB_MAPSIZE_GB'] = '50'

    asyncio.run(precompute_host_a_cache(args.input, args.mapdir, ns, args.workers))
