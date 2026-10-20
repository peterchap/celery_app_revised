# celery_app_revised — canonical home of `dns_module`

This repo is **two things**, and the distinction matters:

1. **The shared DNS engine** — `dns_module/` + `kv/`, published as the pip package
   **`datazag-dns-module`**. This is the *single source of truth* for DNS collection
   across the whole Datazag estate.
2. **The celery worker deployment** around it — `task.py`, `celery_app.py`,
   `master_flight_server.py`, `run_*.py`, `cname_resolver.py`, `*_resolver.py`.
   This is *not* part of the package and is not meant to be imported elsewhere.

> **Rule: never copy `dns_module/` into another repo, and never import it by path.**
> Install the package. A local on-disk copy on `sys.path` silently beats site-packages,
> which has already caused a production outage (every report crashed on a stale lineage —
> see `datazag-pipeline/docs/dns_module-harmonisation.md`). The observatory raises a
> CRITICAL `shadow_risk` alert when it finds a source copy on a host that also has the
> package installed.
>
> That applies to `sys.path.insert()` against a checkout just as much as to a copied
> directory: a path import pins the consumer to whatever that folder last pulled, and the
> version tag stops meaning anything for it. One such path remains in the estate
> (`datazag_intelligence/canonical_collect.py`, the customer-report collector) and is
> tracked as open in the harmonisation doc — do not add another.

## Installing it in another application

Most consumers only resolve names, and that needs none of the parquet tooling:

```bash
pip install "git+ssh://git@github.com/peterchap/celery_app_revised.git@dns-module-v1.7.0"
```

That gives you `DNSFetcher` and the `dns_lookup` helpers. If you run the bulk pipeline —
`DNSApplication`, or `fetch_batch` over parquet — take the `batch` extra instead, which
adds pyarrow, polars and xxhash:

```bash
pip install "datazag-dns-module[batch] @ git+ssh://git@github.com/peterchap/celery_app_revised.git@dns-module-v1.7.0"
```

Pin the tag, not a branch. `pip install -e .` from a checkout also works for local
development. `dns_module.__version__` reports the installed version and is what the
observatory drift guard reads.

The split exists because a single-domain lookup should not cost ~200 MB of columnar
tooling: `pyarrow` is imported by `arrow_schemas`, `batch_processor`, `change_tracker`,
`dns_application`, `infra_risk_enricher`, `ip_batch_processor` and `mx_host_batch`,
`polars` by `infra_risk_enricher`, and `xxhash` by `entity_hasher` — none of which the
`DNSFetcher` path touches. `lmdb`, `loguru` and `aiohttp` stay core, because
`dns_lookup`, `logger` and `policy` import them at module scope. **Before 1.7.0 all ten
were hard dependencies**, so a consumer upgrading from 1.6.x that does batch work must
add `[batch]` or it will lose pyarrow/polars/xxhash. The worker fleet is unaffected: it
clones master and imports by path rather than installing the package.

⚠️ **The ansible `celery_slave` role clones this repo at `version: master`, not at the
tag** — so master is what ships to the worker fleet. When releasing, bump the version in
both `pyproject.toml` and `dns_module/__init__.py`, merge to master, **and** push a
matching `dns-module-vX.Y.Z` tag. If the tag lags master, the fleet and pip consumers run
different code — the exact divergence this package exists to prevent.

## Configuration — read this before your first lookup

The engine defaults to a **local resolver on `127.0.0.1`**, because the worker boxes run
their own Unbound. On any host without one, lookups do not raise — they return
`('TIMEOUT', [], 60)`. If every answer is a timeout, this is why.

Set the resolvers explicitly:

```bash
export DNS_NAMESERVERS="1.1.1.1,8.8.8.8"   # comma-separated
```

| Variable | Default | Purpose |
|---|---|---|
| `DNS_NAMESERVERS` | `127.0.0.1` | Resolvers to query. Honoured by `DNSFetcher` and `DNSApplication`. |
| `DNS_NAMESERVERS_PRIO` | unset | Dedicated fresh-data resolver for `prio_*` workloads (no serve-expired). |
| `DNS_TIMEOUT_S` | `4.0` | Per-query timeout. |
| `DNS_LIFETIME_S` | `12.0` | Total time budget per query incl. retries. |
| `DNS_QPS_LIMIT` | from `CONFIG` | Global rate limit. |
| `DNS_SEMAPHORE_LIMIT` | from `CONFIG` | Max in-flight lookups. |
| `DNS_DISABLE_CACHE` | `0` | Kill-switch — bypass all caching. Set to `1` for live/report lookups. |
| `DNS_LMDB_MAPSIZE_GB` | `10` | LMDB cache size, if the cache is used at all. |

The LMDB cache is **opt-in**: call `dns_lookup.init_lmdb(path)` to enable it. Skip it and
lookups go straight to the resolver — that is the right choice for most consumers.

## Entry points — pick the right layer

There are three, returning **different shapes**. Choosing wrong is what historically
tempted people to fork the module, so pick deliberately.

### 1. `DNSFetcher` — one domain, flat wide record (reports, APIs)

Returns a flat dict of ~85 columns, fully derived (SPF/DMARC parsed, MX chains followed,
PTR resolved, MTA-STS fetched).

```python
import asyncio
from dns_module.dns_fetcher import DNSFetcher
from dns_module import dns_lookup

async def main():
    rec = await DNSFetcher("datazag.com", fetch_mta_sts_policy=False).fetch_records()
    print(rec["status"], rec["a"], rec["mx"], rec["spf"])
    await dns_lookup.shutdown()

asyncio.run(main())
```

```
ALIVE  216.150.1.1  datazag-com.mail.protection.outlook.com  v=spf1 include:spf.protection.outlook.com -all
```

Pass `run_blocking_probes=True` for SMTP banner grabbing; `fetch_mta_sts_policy=False`
skips the HTTP policy fetch when you only need DNS.

### 2. `fetch_batch` — many domains, raw `DNSRecord` (the worker fleet path)

Returns `(results, retries)` of `DNSRecord` objects with just five fields —
`domain`, `status`, `records` (dict keyed by rtype), `errors`, `meta`. **Not** the flat
85-column shape; flatten with `unpack_host_record` / `DNSRecords` if you need columns.

```python
from dns_module.dns_fetcher import fetch_batch

results, retries = await fetch_batch(["datazag.com", "cloudflare.com"], workers=2)
for r in results:
    print(r.domain, r.status, r.records.get("NS"))
```

This is the hot path the fleet uses and the best-tested one. Prefer it for volume.

### 3. `dns_lookup.lookup_*` — single record type, lowest level

`lookup_a`, `lookup_mx`, `lookup_txt`, `lookup_ns`, `lookup_soa`, `lookup_ptr`,
plus `lookup_caa_struct` / `lookup_naptr_struct` / `lookup_srv_struct` for parsed
structured records. Each returns `(rcode, answers, ttl)`.

⚠️ **These bypass `DNS_NAMESERVERS`.** `get_default_resolver()` falls back to a literal
`127.0.0.1` and does not read `CONFIG.nameservers`, so at this layer you must wire the
resolver yourself:

```python
import dns.asyncresolver
from dns_module import dns_lookup

rsv = dns.asyncresolver.Resolver()
rsv.nameservers = ["1.1.1.1"]
dns_lookup.set_default_resolver(rsv)

print(await dns_lookup.lookup_a("datazag.com", use_lmdb=False))   # ('NOERROR', ['216.150.1.1'], 300)
```

Always `await dns_lookup.shutdown()` before exit to drain the LMDB writer and close the
executor.

### `DNSApplication` — the parquet batch pipeline

`DNSApplication(directory, file_key, ...)` is the file-oriented pipeline the fleet runs
(reads a parquet part, writes results and retries). It is deployment machinery, not a
general lookup API — most consumers want `DNSFetcher` or `fetch_batch` instead.

## Adding a capability

Add it **here**, release a version, and upgrade the consumer. Do not fork. If a consumer
needs extras that are genuinely not shared (the way `dns_realtime` needed SMTP banner
analysis), keep those in the consumer as a separate local package layered *on top* of
`dns_module` — the extras may depend on the engine, never the reverse.

## Tests

No venv or lockfile is committed; run the suite through `uv` with explicit deps:

```bash
uv run --no-project --python 3.13 --with pytest --with idna --with tldextract \
  --with dnspython --with loguru --with aiolimiter --with lmdb --with xxhash \
  --with pyarrow --with pytest-asyncio --with python-dotenv python -m pytest tests -q
```

## System context

This repo is one component of the multi-server Datazag pipeline. The system map,
cross-server flows, runbooks and the `dns_module` harmonisation history live in the hub:
`C:\Code\datazag-pipeline` — read its `README.md` and `work/ACTIVE.md` before changes
that touch other components, queues, Flight endpoints or deployed servers.
