import csv
import asyncio
import aiohttp
import time
import os
from tqdm import tqdm

INPUT_FILE = "list.csv"
OUTPUT_FILE = "vout.csv"
PROGRESS_FILE = ".progress.idx"

EXPLORERS = [
    "https://insight.verus.io/api/addr",
    "https://explorer.verus.io/insight-api/addr"
]

CONCURRENCY = 5
RETRIES = 2
TIMEOUT = aiohttp.ClientTimeout(total=15)
CHUNK_SIZE = 1000
DELAY_ON_ERROR = 2.0

# ============ ANSI COLOR ============
GREEN = "\033[92m"
RED = "\033[91m"
RESET = "\033[0m"

# ============ UTIL ============
def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")

# ============ LOAD ============
def load_addresses(path):
    with open(path, encoding="utf-8") as f:
        return [line.strip().split(",")[0] for line in f if line.strip()]

# ============ FETCH ============
async def fetch_balance(session, address):
    for base in EXPLORERS:
        for _ in range(RETRIES):
            try:
                async with session.get(f"{base}/{address}") as r:
                    if r.status != 200:
                        continue
                    data = await r.json()
                    if "balance" in data:
                        return float(data["balance"])
                    if "balanceSat" in data:
                        return float(data["balanceSat"]) / 1e8
            except Exception:
                await asyncio.sleep(0.5)
    return None

# ============ PROCESS CHUNK ============
async def process_chunk(addresses, counters):
    sem = asyncio.Semaphore(CONCURRENCY)
    results = []

    async with aiohttp.ClientSession(timeout=TIMEOUT) as session:

        async def task(addr):
            async with sem:
                bal = await fetch_balance(session, addr)
                return addr, bal

        jobs = [task(a) for a in addresses]

        with tqdm(total=len(jobs), desc="Checking", leave=False) as pbar:
            for coro in asyncio.as_completed(jobs):
                addr, bal = await coro
                results.append((addr, bal))

                if bal is None:
                    counters["error"] += 1
                else:
                    counters["ok"] += 1
                    if bal > 0:
                        counters["positive"] += 1

                pbar.update(1)

    return results

# ============ MAIN ============
def main():
    addresses = load_addresses(INPUT_FILE)
    total = len(addresses)

    start_idx = 0
    if os.path.exists(PROGRESS_FILE):
        start_idx = int(open(PROGRESS_FILE).read().strip())

    counters = {"ok": 0, "error": 0, "positive": 0}

    with open(OUTPUT_FILE, "a", newline="", encoding="utf-8") as out:
        writer = csv.writer(out)

        if start_idx == 0:
            writer.writerow(["address", "balance_vrsc"])

        for i in range(start_idx, total, CHUNK_SIZE):
            chunk = addresses[i:i + CHUNK_SIZE]

            try:
                results = asyncio.run(process_chunk(chunk, counters))
            except Exception:
                print("[!] Error batch, slowdown…")
                time.sleep(DELAY_ON_ERROR)
                continue

            clear_screen()
            print(f"[*] Batch {i} – {i + len(chunk)} / {total}")
            print(f"[+] OK: {counters['ok']} | POSITIVE: {GREEN}{counters['positive']}{RESET} | ERROR: {RED}{counters['error']}{RESET}")
            print("-" * 70)

            for addr, bal in results:
                if bal is None:
                    print(f"{addr} → {RED}ERROR{RESET}")
                elif bal > 0:
                    print(f"{addr} → {GREEN}{bal:.8f}{RESET}")
                    writer.writerow([addr, f"{bal:.8f}"])
                else:
                    print(f"{addr} → {bal:.8f}")

            print("-" * 70)
            print("[+] Menunggu batch berikutnya…")

            with open(PROGRESS_FILE, "w") as p:
                p.write(str(i + CHUNK_SIZE))

            time.sleep(1)

    print("[✓] Selesai")

if __name__ == "__main__":
    main()
