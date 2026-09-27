"""
wallet_tools.py

Single-file Windows-friendly toolkit. Read-only.

Commands:
    python wallet_tools.py rpc          Download EVM chain RPC lists.
    python wallet_tools.py watch        Scan the xpubs below for balances.
    python wallet_tools.py all          Run both.

Requirements:
    pip install requests bitcoinlib

Notes:
    - No private keys are read, derived, or signed with.
    - The watch command is read-only: it queries mempool.space.
    - Works on Windows cmd, PowerShell, and Unix shells.
"""

import sys
import re
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

# ------------------------------------------------------------------
# Shared config
# ------------------------------------------------------------------
HTTP_TIMEOUT   = 15
MAX_WORKERS    = 8          # keep CPU + network modest
CHAIN_URL      = "https://chainid.network/chains.json"
CHAIN_OUT_DIR  = Path("chains")
MEMPOOL_API    = "https://mempool.space/api"
GAP_LIMIT      = 20         # addresses per chain (receive + change)

# ------------------------------------------------------------------
# Replace these with the xpubs you want to watch.
# (Safe to publish; an xpub cannot spend.)
# ------------------------------------------------------------------
WATCH_ACCOUNTS = [
    {
        "name": "Native SegWit (84'/0'/0')",
        "xpub": "xpub6CtLEvaUTzKwAV351MiTtL6vN2eL3gT6rGThf3fDGCG8cXk7nfVV3GppxecGzU1R2jFWYBcaCxxWUrH5unXDgAoCVU9TtoEtU6oY22cCDyz",
        "script_type": "p2wpkh",
    },
    {
        "name": "Taproot (86'/0'/0')",
        "xpub": "xpub6CAxaUqVzcGuLi278K7YpEFKtRPW4PjpSD61VZGxTW3Qne9Cuw4zdRUsJ91GEVNjPJdXKrocXYX4EjFXfaUgYYFtPC41q9znD8UfsUmrhRk",
        "script_type": "p2tr",
    },
    {
        "name": "Nested SegWit (49'/0'/0')",
        "xpub": "xpub6Cce73LKqCgvAmje2KYAbsh4MBKp3WDMVkQxDbEwRYL941iam4XAZcAvPGELde9Lht5ZeSYvTETY1ZiEFuNewzdhw53iXJB2KUAsfLgnhq6",
        "script_type": "p2sh-p2wpkh",
    },
    {
        "name": "Legacy (44'/0'/0')",
        "xpub": "xpub6Bv3DBZu7wk2TfvRbXpFEBsecn5qf9xqUaTHDNXZ6rkEQcz5zfd6LDVTcPmaB2MPHG6pBNQXrTnzPBL1jqR7sRvS34Ewb4qhfDAx7im4aNz",
        "script_type": "p2pkh",
    },
]


# ==================================================================
# PART 1 — RPC downloader
# ==================================================================
def _safe_name(name: str) -> str:
    name = name.strip().lower()
    name = re.sub(r"[^a-z0-9._-]+", "_", name)
    return name.strip("._-") or "unknown"


def run_rpc():
    print("[rpc] fetching chain list…")
    r = requests.get(CHAIN_URL, timeout=HTTP_TIMEOUT)
    r.raise_for_status()
    chains = r.json()

    CHAIN_OUT_DIR.mkdir(exist_ok=True)
    written = 0
    for chain in chains:
        rpcs = chain.get("rpc", [])
        if not rpcs:
            continue
        cid  = chain.get("chainId", "unknown")
        name = _safe_name(chain.get("name", "unknown"))
        path = CHAIN_OUT_DIR / f"{cid}_{name}.txt"

        seen = set()
        with path.open("w", encoding="utf-8") as f:
            for url in rpcs:
                if url not in seen:
                    seen.add(url)
                    f.write(url + "\n")
        written += 1

    print(f"[rpc] wrote {written} files to {CHAIN_OUT_DIR.resolve()}")


# ==================================================================
# PART 2 — Watch-only xpub scanner
# ==================================================================
def _utxos(addr: str):
    try:
        r = requests.get(f"{MEMPOOL_API}/address/{addr}/utxo", timeout=HTTP_TIMEOUT)
        if r.status_code == 200:
            return r.json()
    except requests.RequestException:
        return []
    return []


def _derive_batch(xpub: str, script_type: str, gap: int):
    """Return list of (chain, index, address). Imported lazily."""
    from bitcoinlib.keys import HDKey
    hd = HDKey(xpub)
    out = []
    for chain in (0, 1):
        for idx in range(gap):
            child = hd.child(chain).child(idx)
            out.append((chain, idx, child.address(script_type=script_type)))
    return out


def _scan_account(account):
    name        = account["name"]
    xpub        = account["xpub"]
    script_type = account["script_type"]

    print(f"\n[watch] {name}")
    print(f"[watch] xpub: {xpub[:44]}…")

    try:
        addrs = _derive_batch(xpub, script_type, GAP_LIMIT)
    except Exception as e:
        print(f"[watch] derivation failed: {e}")
        return 0

    total = 0
    hits  = 0

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(_utxos, a): (c, i, a) for c, i, a in addrs}
        for fut in as_completed(futures):
            chain, idx, addr = futures[fut]
            try:
                utxos = fut.result()
            except Exception:
                continue
            if not utxos:
                continue
            value = sum(u["value"] for u in utxos)
            total += value
            hits  += 1
            label = "receive" if chain == 0 else "change"
            print(f"  [{label} {idx}] {addr}  {value} sats  ({len(utxos)} UTXOs)")

    if hits == 0:
        print("  no UTXOs found in scanned range")
    print(f"  total: {total} sats ({total / 1e8:.8f} BTC)")
    return total


def run_watch():
    print("[watch] read-only scan, no signing")
    grand = 0
    for acct in WATCH_ACCOUNTS:
        grand += _scan_account(acct)
    print(f"\n[watch] grand total across accounts: {grand} sats "
          f"({grand / 1e8:.8f} BTC)")


# ==================================================================
# CLI
# ==================================================================
def main():
    cmd = sys.argv[1].lower() if len(sys.argv) > 1 else "all"

    if cmd == "rpc":
        run_rpc()
    elif cmd == "watch":
        run_watch()
    elif cmd == "all":
        run_rpc()
        print()
        run_watch()
    else:
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
