#!/usr/bin/env python3
"""
ProNetScanner — two-stage port scanner.

Stage 1: Fast asyncio TCP-connect sweep across all 65535 ports.
Stage 2: Hand the open ports to nmap for deep service/version/script scanning.

Usage:
    python pronetscanner.py <target> [--ports 1-65535] [--concurrency 2000]
                            [--timeout 1.0] [--nmap-args "-sV -sC -O"]
"""

import argparse
import asyncio
import shutil
import subprocess
import sys
import time


async def probe(host: str, port: int, timeout: float, sem: asyncio.Semaphore,
                retries: int = 2):
    for attempt in range(1 + retries):
        async with sem:
            try:
                fut = asyncio.open_connection(host, port)
                reader, writer = await asyncio.wait_for(fut, timeout=timeout)
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                return port
            except ConnectionRefusedError:
                return None
            except (asyncio.TimeoutError, OSError):
                if attempt < retries:
                    await asyncio.sleep(0.2 * (attempt + 1))
                    continue
                return None


async def fast_sweep(host: str, ports, concurrency: int, timeout: float,
                     retries: int = 2):
    sem = asyncio.Semaphore(concurrency)
    tasks = [asyncio.create_task(probe(host, p, timeout, sem, retries=retries))
             for p in ports]
    open_ports = []
    total = len(tasks)
    done = 0
    for coro in asyncio.as_completed(tasks):
        result = await coro
        done += 1
        if result is not None:
            open_ports.append(result)
            print(f"  [+] {host}:{result} open")
        if done % 2000 == 0 or done == total:
            print(f"  ... swept {done}/{total} ports", file=sys.stderr)
    return sorted(open_ports)


def parse_ports(spec: str):
    out = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if "-" in chunk:
            a, b = chunk.split("-", 1)
            out.update(range(int(a), int(b) + 1))
        else:
            out.add(int(chunk))
    return sorted(p for p in out if 1 <= p <= 65535)


def deep_scan(host: str, open_ports, nmap_args: str):
    nmap = shutil.which("nmap")
    if not nmap:
        print("[!] nmap not found in PATH — skipping deep scan.", file=sys.stderr)
        print("    Open ports:", ",".join(map(str, open_ports)))
        return
    if not open_ports:
        print("[!] No open ports — nothing for nmap to inspect.")
        return
    port_list = ",".join(map(str, open_ports))
    cmd = [nmap, *nmap_args.split(), "-p", port_list, host]
    print(f"\n[>] Running: {' '.join(cmd)}\n")
    subprocess.run(cmd)


def main():
    ap = argparse.ArgumentParser(description="Fast two-stage port scanner.")
    ap.add_argument("target", help="Hostname or IP to scan")
    ap.add_argument("--ports", default="1-65535", help="Port spec, e.g. 1-65535 or 22,80,443")
    ap.add_argument("--concurrency", type=int, default=2000, help="Parallel sockets")
    ap.add_argument("--timeout", type=float, default=1.0, help="Per-port timeout (s)")
    ap.add_argument("--retries", type=int, default=2,
                    help="Per-port retries on timeout/error (0 to disable)")
    ap.add_argument("--nmap-args", default="-sV -sC -Pn -T4",
                    help="Flags passed to nmap for the deep scan")
    args = ap.parse_args()

    ports = parse_ports(args.ports)
    print(f"[*] Stage 1: fast sweep of {len(ports)} ports on {args.target} "
          f"(concurrency={args.concurrency}, timeout={args.timeout}s, "
          f"retries={args.retries})")
    t0 = time.time()
    try:
        open_ports = asyncio.run(
            fast_sweep(args.target, ports, args.concurrency, args.timeout,
                       args.retries)
        )
    except KeyboardInterrupt:
        print("\n[!] Aborted.")
        sys.exit(1)
    dt = time.time() - t0
    print(f"\n[*] Sweep finished in {dt:.1f}s — {len(open_ports)} open: "
          f"{','.join(map(str, open_ports)) or '(none)'}")

    print("\n[*] Stage 2: deep scan with nmap")
    deep_scan(args.target, open_ports, args.nmap_args)


if __name__ == "__main__":
    main()
