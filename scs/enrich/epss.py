"""FIRST EPSS: probability that a CVE is exploited in the next 30 days."""
from __future__ import annotations

import time

from scs.util import cache_dir, http_json, read_json, write_json

URL = "https://api.first.org/data/v1/epss?cve={}"
TTL = 24 * 3600
BATCH = 80


def scores(cves: list[str], offline: bool = False) -> dict[str, float]:
    path = cache_dir() / "epss.json"
    cache: dict = read_json(path) if path.exists() else {}
    now = time.time()
    out: dict[str, float] = {}
    todo = []
    for c in cves:
        hit = cache.get(c)
        if hit and (offline or now - hit["t"] < TTL):
            if hit["s"] is not None:
                out[c] = hit["s"]
        else:
            todo.append(c)
    if not offline:
        for i in range(0, len(todo), BATCH):
            chunk = todo[i:i + BATCH]
            resp = http_json(URL.format(",".join(chunk)) + f"&limit={BATCH}")
            got = {d["cve"]: float(d["epss"]) for d in resp.get("data", [])}
            for c in chunk:
                cache[c] = {"t": now, "s": got.get(c)}
                if c in got:
                    out[c] = got[c]
        write_json(path, cache)
    return out
