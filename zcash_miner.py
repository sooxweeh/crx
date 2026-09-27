#!/usr/bin/env python3
"""
Zcash Solo CPU Miner — Single-File Production Script
Wallet: t1dGo14mZWkZkxgSQZ3gxdNGHfReT2C8WsK

Dependencies:
    pip install pyequihash requests

Requires a running, fully-synced zcashd node with RPC enabled.

WARNING: CPU solo mining Zcash is economically unviable vs ASICs.
This script is for protocol-level education and testing.
"""

import os, sys, time, json, struct, hashlib, subprocess
from binascii import hexlify, unhexlify
import requests

# ═══════════════════════════════════════════════════════════════════
#  CONFIG — EDIT THESE
# ═══════════════════════════════════════════════════════════════════
RPC_USER     = "zcashrpc"
RPC_PASSWORD = "YourStrongPasswordHere"
RPC_HOST     = "127.0.0.1"
RPC_PORT     = 8232
WALLET       = "t1dGo14mZWkZkxgSQZ3gxdNGHfReT2C8WsK"

# CPU throttle: sleep between nonce batches.
# 0.0 = max CPU | 0.5 = light | 1.0 = very light | 2.0 = minimal
THROTTLE_SEC = 0.5
BATCH_SIZE   = 5          # nonces per Equihash attempt before sleep

# ═══════════════════════════════════════════════════════════════════
#  EQUIHASH SOLVER IMPORT
# ═══════════════════════════════════════════════════════════════════
try:
    import equihash as _eq
    HAVE_EQ = True
except ImportError:
    HAVE_EQ = False
    print("[!] pyequihash not installed.")
    print("[!] Run: pip install pyequihash requests")
    print("[!] It requires libequihash + libsodium (C libraries).")
    sys.exit(1)

# ═══════════════════════════════════════════════════════════════════
#  BASE58CHECK — t-address → hash160
# ═══════════════════════════════════════════════════════════════════
_B58 = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def b58decode(s: str) -> bytes:
    n = 0
    for c in s.encode():
        n = n * 58 + _B58.index(c)
    pad = 0
    for c in s.encode():
        if c == ord('1'): pad += 1
        else: break
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\x00" * pad + body

def address_to_hash160(addr: str) -> bytes:
    raw = b58decode(addr)
    if len(raw) != 26:
        raise ValueError(f"Bad address length: {len(raw)}")
    if raw[:2] != b"\x1c\xb8":
        raise ValueError("Not a mainnet t1 P2PKH address")
    payload = raw[2:22]
    expected = hashlib.sha256(hashlib.sha256(raw[:22]).digest()).digest()[:4]
    if raw[22:] != expected:
        raise ValueError("Bad address checksum")
    return payload

def p2pkh_script(h160: bytes) -> bytes:
    assert len(h160) == 20
    return b"\x76\xa9\x14" + h160 + b"\x88\xac"

# ═══════════════════════════════════════════════════════════════════
#  RPC
# ═══════════════════════════════════════════════════════════════════
class RPC:
    def __init__(self):
        self.url  = f"http://{RPC_HOST}:{RPC_PORT}"
        self.auth = (RPC_USER, RPC_PASSWORD)
        self.hdr  = {"Content-Type": "application/json"}
        self._id  = 0

    def call(self, method, params=None):
        self._id += 1
        payload = {"jsonrpc":"1.0","id":self._id,
                   "method":method,"params":params or []}
        try:
            r = requests.post(self.url, auth=self.auth, headers=self.hdr,
                              data=json.dumps(payload), timeout=30)
            r.raise_for_status()
            j = r.json()
            if j.get("error"):
                print(f"[RPC] {method}: {j['error']}")
                return None
            return j["result"]
        except requests.exceptions.ConnectionError:
            print("[RPC] Cannot connect. Is zcashd running & synced?")
            return None
        except Exception as e:
            print(f"[RPC] {e}")
            return None

    def gbt(self):          return self.call("getblocktemplate",
                                            [{"capabilities":["workid"]}])
    def submit(self, blk):  return self.call("submitblock", [blk])
    def info(self):         return self.call("getblockchaininfo")

# ═══════════════════════════════════════════════════════════════════
#  SERIALIZATION HELPERS
# ═══════════════════════════════════════════════════════════════════
def varint(n: int) -> bytes:
    if n < 0xfd:            return struct.pack("<B", n)
    elif n <= 0xffff:       return struct.pack("<BH", 0xfd, n)
    elif n <= 0xffffffff:   return struct.pack("<BI", 0xfe, n)
    else:                   return struct.pack("<BQ", 0xff, n)

def sha256d(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()

def merkle_root(txids):
    if not txids: return b"\x00"*32
    layer = list(txids)
    if len(layer) == 1: return layer[0]
    while len(layer) > 1:
        if len(layer) % 2: layer.append(layer[-1])
        layer = [sha256d(layer[i]+layer[i+1]) for i in range(0,len(layer),2)]
    return layer[0]

def bits_to_target(bits: int) -> int:
    exp  = bits >> 24
    mant = bits & 0x007fffff
    if exp <= 3: return mant >> (8*(3-exp))
    return mant << (8*(exp-3))

# ═══════════════════════════════════════════════════════════════════
#  COINBASE (Zcash v4 transparent)
# ═══════════════════════════════════════════════════════════════════
def build_coinbase(height: int, value: int, h160: bytes, extra: bytes) -> bytes:
    h = height
    hb = b""
    while h > 0:
        hb = bytes([h & 0xff]) + hb
        h >>= 8
    script_sig = bytes([len(hb)]) + hb + extra

    tx  = struct.pack("<I", 4)                       # version
    tx += varint(1)                                  # vin count
    tx += b"\x00"*32 + struct.pack("<I", 0xffffffff) # null prevout
    tx += varint(len(script_sig)) + script_sig
    tx += struct.pack("<I", 0xffffffff)              # sequence

    tx += varint(1)                                  # vout count
    tx += struct.pack("<Q", value)                   # value
    spk = p2pkh_script(h160)
    tx += varint(len(spk)) + spk

    tx += struct.pack("<I", 0)                       # locktime
    tx += struct.pack("<I", 0)                       # expiryHeight
    tx += struct.pack("<q", 0)                       # valueBalance
    tx += varint(0)                                  # shieldedSpendCount
    tx += varint(0)                                  # shieldedOutputCount
    return tx

# ═══════════════════════════════════════════════════════════════════
#  BLOCK HEADER (Zcash — 140-byte pre-solution + solution)
# ═══════════════════════════════════════════════════════════════════
def serialize_pre_header(version, prev_hash, merkle, sapling,
                         ntime, bits, nonce32):
    return (struct.pack("<i", version) +
            unhexlify(prev_hash)[::-1] +
            merkle[::-1] +
            unhexlify(sapling)[::-1] +
            struct.pack("<I", ntime) +
            struct.pack("<I", bits) +
            nonce32)

# ═══════════════════════════════════════════════════════════════════
#  EQUIHASH SOLVE (via pyequihash)
# ═══════════════════════════════════════════════════════════════════
def solve_equihash(pre_header: bytes):
    """
    Call pyequihash.solve(200, 9, seed).
    seed = pre_header (140 bytes).
    Returns solution bytes, or None.
    """
    try:
        sol = _eq.solve(200, 9, pre_header)
        if sol is None:
            return None
        if isinstance(sol, (bytes, bytearray)):
            return bytes(sol)
        # Some builds return a list of ints
        if isinstance(sol, list):
            out = b""
            for x in sol:
                out += struct.pack("<I", x & 0xffffffff)
            return out
        return None
    except Exception as e:
        print(f"[Equihash] solve error: {e}")
        return None

# ═══════════════════════════════════════════════════════════════════
#  MAIN MINER
# ═══════════════════════════════════════════════════════════════════
def main():
    print("=" * 64)
    print("  ZCASH SOLO CPU MINER — pyequihash + RPC")
    print("=" * 64)

    # Decode wallet
    try:
        h160 = address_to_hash160(WALLET)
    except Exception as e:
        print(f"[!] Address error: {e}")
        sys.exit(1)
    print(f"[+] Wallet:  {WALLET}")
    print(f"[+] hash160: {h160.hex()}")

    # Connect
    rpc = RPC()
    info = rpc.info()
    if not info:
        print("[!] Cannot reach zcashd. Check zcash.conf and daemon status.")
        sys.exit(1)
    print(f"[+] Chain: {info.get('chain')} | Blocks: {info.get('blocks'):,}")
    if info.get("chain") != "main":
        print("[!] WARNING: not on mainnet.")
    if info.get("blocks", 0) < 100:
        print("[!] WARNING: node may not be synced yet.")

    # Windows: set BELOW_NORMAL priority
    if sys.platform == "win32":
        try:
            import ctypes
            k32 = ctypes.windll.kernel32
            k32.SetPriorityClass(k32.GetCurrentProcess(), 0x00004000)
            print("[+] Process priority: BELOW_NORMAL")
        except Exception:
            pass

    print(f"[+] Throttle: {THROTTLE_SEC}s per {BATCH_SIZE} nonces")
    print(f"[+] Equihash: 200, 9 (via pyequihash)\n")
    print("[*] Press Ctrl+C to stop.\n")

    stats = {"blocks": 0, "nonces": 0, "start": time.time()}

    while True:
        tmpl = rpc.gbt()
        if not tmpl:
            time.sleep(5); continue

        height    = tmpl["height"]
        prev_hash = tmpl["previousblockhash"]
        bits_s    = tmpl["bits"]
        bits      = int(bits_s, 16) if isinstance(bits_s, str) else bits_s
        curtime   = tmpl["curtime"]
        version   = tmpl["version"]
        sapling   = tmpl.get("finalsaplingroot", "00"*32)
        cb_value  = tmpl["coinbasevalue"]
        other_txs = [t["data"] for t in tmpl.get("transactions", [])]

        stats["blocks"] += 1
        target = bits_to_target(bits)

        print(f"\n{'─'*64}")
        print(f"[*] Block #{height} | prev {prev_hash[:20]}... | "
              f"txs {len(other_txs)} | target 0x{target:064x}")
        print(f"{'─'*64}")

        nonce_i = 0
        while True:
            # Refresh template every BATCH_SIZE nonces
            if nonce_i and nonce_i % BATCH_SIZE == 0:
                fresh = rpc.gbt()
                if fresh and fresh["height"] != height:
                    print("[*] New block — restarting.")
                    break

            # ── Build coinbase ──
            extra     = struct.pack("<Q", nonce_i)
            cb        = build_coinbase(height, cb_value, h160, extra)
            cb_txid   = sha256d(cb)
            txids     = [cb_txid] + [sha256d(unhexlify(t)) for t in other_txs]
            mroot     = merkle_root(txids)

            # ── 32-byte nonce ──
            nonce32   = struct.pack("<Q", nonce_i) + b"\x00" * 24

            # ── Pre-solution header (140 bytes) ──
            pre_hdr   = serialize_pre_header(version, prev_hash, mroot,
                                             sapling, curtime, bits, nonce32)

            # ── Solve ──
            t0  = time.time()
            sol = solve_equihash(pre_hdr)
            dt  = time.time() - t0
            stats["nonces"] += 1

            if sol:
                full_hdr = pre_hdr + varint(len(sol)) + sol
                blk_hash = sha256d(full_hdr)
                h_int    = int.from_bytes(blk_hash[::-1], "big")

                print(f"\n[+] Solution found (nonce {nonce_i}, "
                      f"{dt:.2f}s)")
                print(f"    hash: {blk_hash[::-1].hex()}")

                if h_int <= target:
                    all_txs = [cb] + [unhexlify(t) for t in other_txs]
                    block   = full_hdr + varint(len(all_txs)) + b"".join(all_txs)
                    print(f"[!!!] BLOCK VALID — submitting {len(block)} bytes")
                    res = rpc.submit(block.hex())
                    if res is None:
                        print("[+] submitblock returned null → ACCEPTED")
                    else:
                        print(f"[!] submitblock result: {res}")
                    break
                else:
                    print("    (solution did not meet target — continuing)")

            nonce_i += 1

            # Progress every 20 nonces
            if nonce_i % 20 == 0:
                el   = time.time() - stats["start"]
                rate = stats["nonces"] / el if el else 0
                print(f"\r    nonces: {stats['nonces']:,} | "
                      f"{rate:.3f}/s | blocks: {stats['blocks']}",
                      end="", flush=True)

            # ── CPU THROTTLE ──
            if nonce_i % BATCH_SIZE == 0:
                time.sleep(THROTTLE_SEC)

# ═══════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[*] Stopped by user.")
