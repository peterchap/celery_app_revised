import asyncio
import os
from typing import List, Dict, Any

import pyarrow as pa
import pyarrow.parquet as pq

from dns_module import dns_lookup
from dns_module.dns_utils import reg_domain

async def seed_from_ip_asn(input_path: str, out_parquet: str, lmdb_dir: str, ptr_dir: str, nameservers: List[str], workers: int) -> None:
    # Initialize LMDBs in write mode on master
    dns_lookup.init_lmdb(lmdb_dir, readonly=False, lock=True)
    dns_lookup.init_lmdb_ptr(ptr_dir, readonly=False, lock=True)
    resolver = dns_lookup.get_default_resolver(nameservers=nameservers)
    sem = dns_lookup.default_semaphore(limit=max(workers, 1))

    rows: List[Dict[str, Any]] = []

    async def process_row(ip: str, asn: str):
        ip = (ip or '').strip()
        asn = (asn or '').strip()
        if not ip:
            return
        # PTR
        try:
            import ipaddress
            reverse_name = ipaddress.ip_address(ip).reverse_pointer
        except Exception:
            reverse_name = None
        ptr_target = None
        if reverse_name:
            try:
                # Try cache first (PTR LMDB)
                cached = await dns_lookup.get_cached_result('PTR', reverse_name, only_positive=True, env_name='ptr')
            except Exception:
                cached = None
            if cached and cached[1]:
                ptr_target = str(cached[1][0]).rstrip('.')
            else:
                # Live PTR and write to PTR LMDB
                try:
                    r_ptr, a_ptr, ttl_ptr = await dns_lookup.lookup_ptr(reverse_name, resolver, sem)
                    if r_ptr == 'NOERROR' and a_ptr:
                        ptr_target = str(a_ptr[0]).rstrip('.')
                        # write to PTR LMDB
                        try:
                            env_ptr = dns_lookup._lmdb_env_ptr
                            if env_ptr is not None:
                                key = dns_lookup._cache_key('PTR', reverse_name)
                                val = dns_lookup._serialize_value(r_ptr, a_ptr, ttl_ptr)
                                with env_ptr.begin(write=True) as txn:
                                    txn.put(key.encode('utf-8'), val)
                        except Exception:
                            pass
                except Exception:
                    pass
        # Derive domain from PTR and get MX + MX host A/AAAA
        mx_host = None
        mx_rcode = None
        mx_answers: List[str] = []
        mx_a: List[str] = []
        mx_aaaa: List[str] = []
        domain = None
        if ptr_target:
            domain = reg_domain(ptr_target) or None
        if domain:
            try:
                mx_rcode, mx_answers, _ = await dns_lookup.lookup_mx(domain, resolver, sem)
            except Exception:
                mx_rcode, mx_answers = None, []
            if mx_rcode == 'NOERROR' and mx_answers:
                try:
                    parts = str(mx_answers[0]).split(':', 1)
                    mx_host = (parts[1] if len(parts) == 2 else str(mx_answers[0])).rstrip('.')
                except Exception:
                    mx_host = None
                if mx_host:
                    # resolve A/AAAA for mx_host, write to forward LMDB via normal path
                    try:
                        r_a, a_list, _ = await dns_lookup.lookup_a(mx_host, resolver, sem)
                        if r_a == 'NOERROR' and a_list:
                            mx_a = [str(x) for x in a_list]
                    except Exception:
                        pass
                    try:
                        r_aaaa, aaaa_list, _ = await dns_lookup.lookup_aaaa(mx_host, resolver, sem)
                        if r_aaaa == 'NOERROR' and aaaa_list:
                            mx_aaaa = [str(x) for x in aaaa_list]
                    except Exception:
                        pass
        rows.append({
            'ip': ip,
            'asn': asn,
            'ptr': ptr_target,
            'domain': domain,
            'mx_rcode': mx_rcode,
            'mx': mx_answers,
            'mx_host': mx_host,
            'mx_host_a': mx_a,
            'mx_host_aaaa': mx_aaaa,
        })

    async def run():
        # Read input as TSV/CSV with ip,asn columns (auto-detect by delimiter)
        sem_local = asyncio.Semaphore(workers)
        tasks = []
        with open(input_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                # naive split: try tab first then comma
                parts = line.split('\t') if ('\t' in line) else line.split(',')
                ip = parts[0].strip() if parts else ''
                asn = parts[1].strip() if len(parts) > 1 else ''
                async def _wrapped(ip=ip, asn=asn):
                    async with sem_local:
                        await process_row(ip, asn)
                tasks.append(asyncio.create_task(_wrapped()))
                if len(tasks) >= workers * 50:
                    await asyncio.gather(*tasks)
                    tasks.clear()
        if tasks:
            await asyncio.gather(*tasks)

    await run()

    # Write parquet
    table = pa.Table.from_pylist(rows)
    pq.write_table(table, out_parquet)

    # Shutdown
    await dns_lookup.shutdown()

if __name__ == '__main__':
    # Defaults are embedded for automated runs; override via environment if needed
    input_path = os.getenv('IP_ASN_INPUT', '/mnt/shared/ip_asn.tsv')
    out_parquet = os.getenv('IP_ASN_PARQUET_OUT', '/mnt/shared/parquet/ip_asn_seed.parquet')
    lmdb_dir = os.getenv('LMDB_DIR', '/mnt/shared/dns_lmdb')
    ptr_dir = os.getenv('DNS_LMDB_PTR_DIR', '/mnt/shared/dns_lmdb_ptr')
    nameservers = [s.strip() for s in (os.getenv('NAMESERVERS', '127.0.0.1')).split(',') if s.strip()]
    workers = int(os.getenv('SEED_WORKERS', '400'))
    asyncio.run(seed_from_ip_asn(input_path, out_parquet, lmdb_dir, ptr_dir, nameservers, workers))
