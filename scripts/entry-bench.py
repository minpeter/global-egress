#!/usr/bin/env python3
"""Compare candidate entry tunnels for a set of exit countries.

Each candidate runs alone in its own short-lived instance, so the numbers reflect
that entry only and not the pool's learned preference. This is how you decide
which entries to configure for a given deployment location.

Usage: scripts/entry-bench.py <catalog.zip> <entry,entry,...> <cc,cc,...>
"""

import json
import os
import signal
import statistics
import subprocess
import sys
import tempfile
import time
import urllib.request

BINARY = "./bin/global-egress"
HTTP_PORT = 12128
CONTROL_PORT = 12280
SAMPLES_PER_COUNTRY = 3


def wait_ready(timeout: float = 25.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(
                f"http://127.0.0.1:{CONTROL_PORT}/v1/stats", timeout=2
            ) as response:
                stats = json.load(response)
                if stats.get("entries_open", 0) > 0:
                    return True
        except Exception:  # noqa: BLE001 - the server may not be listening yet
            pass
        time.sleep(0.5)
    return False


def timed_request(country: str, timeout: int = 45) -> float | None:
    """Return seconds taken to fetch through an exit in country, or None."""
    proxy = f"http://cc={country}:x@127.0.0.1:{HTTP_PORT}"
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": proxy, "https": proxy})
    )
    started = time.monotonic()
    try:
        with opener.open("https://am.i.mullvad.net/ip", timeout=timeout) as response:
            response.read()
    except Exception:  # noqa: BLE001 - a failed exit is simply not a sample
        return None
    return time.monotonic() - started


def render_config(catalog: str, entry: str, state_dir: str) -> str:
    """Render the strict TOML service config for one benchmarked entry."""
    return f"""
mode = "relay-socks"
state_dir = "{state_dir}"

[listen]
socks5 = ""
http = "127.0.0.1:{HTTP_PORT}"
control = "127.0.0.1:{CONTROL_PORT}"

[access]
allowed_clients = ["127.0.0.1/32"]

[pool]
max_active = 5
preopen = 1

[log]
level = "error"

[[providers]]
id = "mullvad"
type = "mullvad"
enabled = true

[providers.catalog]
path = "{catalog}"

[providers.relays]
url = "https://api.mullvad.net/www/relays/wireguard/"
cache = "relays.json"
refresh = "24h"

[providers.entries]
slots = ["{entry}"]
"""


def bench_entry(catalog: str, entry: str, countries: list[str]) -> dict[str, float]:
    # The config lives in a temp directory, and relative paths in a config are
    # resolved against the config's own directory, so everything must be absolute.
    catalog = os.path.abspath(catalog)
    state_dir = os.path.abspath(".local-state")
    config = render_config(catalog, entry, state_dir)
    with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as handle:
        handle.write(config)
        config_path = handle.name

    process = subprocess.Popen(
        [BINARY, "serve", "-config", config_path],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    results: dict[str, float] = {}
    try:
        if not wait_ready():
            print(f"  {entry}: entry never came up")
            return results
        for country in countries:
            samples = [timed_request(country) for _ in range(SAMPLES_PER_COUNTRY)]
            good = [s for s in samples if s is not None]
            if good:
                results[country] = statistics.median(good)
    finally:
        os.killpg(os.getpgid(process.pid), signal.SIGTERM)
        process.wait(timeout=15)
        os.unlink(config_path)
    return results


def main() -> int:
    if len(sys.argv) < 4:
        print(__doc__)
        return 2
    catalog = sys.argv[1]
    entries = [e.strip() for e in sys.argv[2].split(",") if e.strip()]
    countries = [c.strip() for c in sys.argv[3].split(",") if c.strip()]

    table: dict[str, dict[str, float]] = {}
    for entry in entries:
        print(f"benchmarking entry {entry} ...", flush=True)
        table[entry] = bench_entry(catalog, entry, countries)

    header = "entry".ljust(18) + "".join(cc.rjust(9) for cc in countries) + "   median"
    print("\n" + header)
    print("-" * len(header))
    for entry, results in table.items():
        cells = ""
        for country in countries:
            value = results.get(country)
            cells += (f"{value * 1000:.0f}ms".rjust(9)) if value else "    n/a".rjust(9)
        overall = statistics.median(results.values()) if results else 0
        print(f"{entry:<18}{cells}   {overall * 1000:.0f}ms" if overall else f"{entry:<18}{cells}")

    print("\nbest entry per exit country:")
    for country in countries:
        ranked = sorted(
            ((entry, res[country]) for entry, res in table.items() if country in res),
            key=lambda kv: kv[1],
        )
        if not ranked:
            print(f"  {country}: no samples")
            continue
        winner, best = ranked[0]
        runner = f", next {ranked[1][0]} {ranked[1][1] * 1000:.0f}ms" if len(ranked) > 1 else ""
        print(f"  {country}: {winner} {best * 1000:.0f}ms{runner}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
