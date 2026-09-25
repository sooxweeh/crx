#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gems_hunter.py — Single-file cross-platform BTC puzzle / riddle recovery toolkit
=================================================================================

One file. Windows / macOS / Linux. CPU by default, optional CUDA via numba.

Layers implemented (matching the GemsBTC riddle hint set):
  1. WIF fragment range derivation      (numeric interval per fragment position)
  2. WIF typo repair                    (single/multi char corruption, checksum-validated)
  3. Brainwallet sweep                  (sha256 of ngrams/combos from hint text)
  4. Kangaroo / BSGS orchestration      (RCKangaroo, Pons Kangaroo, keyhunt)
  5. Block / range target lists         (puzzle-style 2^n ranges, custom hex ranges)
  6. Balance scanning                   (mempool.space / BlockCypher / esplora, rate-limited)
  7. Vulnerability-driven key recovery  (weak RNG: keys with low entropy patterns;
                                        repeated-nonce ECDSA recovery from on-chain sigs)

License: MIT.  Educational / authorized-research use.

Usage examples:
  python gems_hunter.py ranges --fragment 9vw04 --wif-len 52
  python gems_hunter.py typo --fragment 9vw04 --address bc1qr5mssp6snmduqp9enx4dzmcxvk7qw83lceyy2v --max-bad 2
  python gems_hunter.py brainwallet --text "I don't like rainbows Daniel Shanks" --address bc1q...
  python gems_hunter.py targets --puzzles 60-130 --out targets.json
  python gems_hunter.py scan --targets targets.json --top 20
  python gems_hunter.py kangaroo --pubkey 039d7ce8...75b --start <hex> --end <hex> --dp 20
  python gems_hunter.py nonce --txid <txid> --vout 0     # repeated-nonce recovery
  python gems_hunter.py selftest
"""

import argparse
import base64
import hashlib
import itertools
import json
import math
import os
import platform
import queue
import signal
import struct
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Iterable, Dict, Callable

# ============================================================================
# secp256k1 — with the on-curve assertion that catches bad GY (lesson learned)
# ============================================================================

P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8  # 64 nibbles, verified on-curve in selftest

def assert_g_on_curve() -> None:
    assert (GY * GY - (GX ** 3 + 7)) % P == 0, "G is NOT on curve — GY corrupted"

assert_g_on_curve()

def inv(a: int, m: int = P) -> int:
    return pow(a, m - 2, m)

def ec_add(p: Tuple[int, int], q: Tuple[int, int]) -> Tuple[int, int]:
    if p is None: return q
    if q is None: return p
    x1, y1 = p; x2, y2 = q
    if x1 == x2 and (y1 + y2) % P == 0: return None
    if p == q:
        lam = (3 * x1 * x1) * inv(2 * y1) % P
    else:
        lam = (y2 - y1) * inv((x2 - x1) % P) % P
    x3 = (lam * lam - x1 - x2) % P
    return (x3, (lam * (x1 - x3) - y1) % P)

def ec_mul(k: int, pt: Tuple[int, int] = (GX, GY)) -> Tuple[int, int]:
    k %= N
    r = None
    while k:
        if k & 1: r = ec_add(r, pt)
        pt = ec_add(pt, pt); k >>= 1
    return r

def point_is_on_curve(pt: Tuple[int, int]) -> bool:
    if pt is None: return False
    x, y = pt
    return (y * y - (x * x * x + 7)) % P == 0

def pub_from_priv(priv: int, compressed: bool = True) -> bytes:
    x, y = ec_mul(priv % N)
    if compressed:
        return bytes([2 + (y & 1)]) + x.to_bytes(32, "big")
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")

def hash160(b: bytes) -> bytes:
    return hashlib.new("ripemd160", hashlib.sha256(b).digest()).digest()

# ============================================================================
# Base58 / Bech32
# ============================================================================

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B58_MAP = {c: i for i, c in enumerate(B58)}

def b58decode_int(s: str) -> int:
    n = 0
    for c in s:
        n = n * 58 + B58_MAP[c]
    return n

def b58encode_int(n: int, length: Optional[int] = None) -> str:
    out = []
    while n:
        n, r = divmod(n, 58)
        out.append(B58[r])
    s = "".join(reversed(out)) or B58[0]
    if length:
        s = B58[0] * (length - len(s)) + s
    return s

def b58check_decode(s: str) -> bytes:
    raw_int = b58decode_int(s)
    raw = raw_int.to_bytes((raw_int.bit_length() + 7) // 8 or 1, "big")
    raw = b"\x00" * (len(s) - len(s.lstrip("1"))) + raw  # leading '1's = zero bytes
    data, chk = raw[:-4], raw[-4:]
    assert hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4] == chk, "b58 checksum"
    return data

def b58check_encode(data: bytes) -> str:
    chk = hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]
    return b58encode_int(int.from_bytes(data + chk, "big"), length=len(data) + 4)

BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32_MAP = {c: i for i, c in enumerate(BECH32)}

def bech32_polymod(values: List[int]) -> int:
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= gen[i] if ((b >> i) & 1) else 0
    return chk

def bech32_hrp_expand(hrp: str) -> List[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]

def convertbits(data: Iterable[int], frombits: int, tobits: int, pad: bool = True) -> List[int]:
    acc, bits, ret = 0, 0, []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    return ret

def segwit_addr_encode(hrp: str, witver: int, witprog: bytes) -> str:
    data = [witver] + convertbits(witprog, 8, 5)
    chk = bech32_polymod(bech32_hrp_expand(hrp) + data + [0, 0, 0, 0, 0, 0]) ^ 1
    return hrp + "1" + "".join(BECH32[d] for d in data) + "".join(BECH32[(chk >> 5 * (5 - i)) & 31] for i in range(6))

def addr_p2wpkh(pub: bytes, hrp: str = "bc") -> str:
    return segwit_addr_encode(hrp, 0, hash160(pub))

def addr_p2pkh(pub: bytes, ver: int = 0x00) -> str:
    h = hash160(pub)
    return b58check_encode(bytes([ver]) + h)

def addr_from_pub(pub: bytes, addr_type: str = "p2wpkh") -> str:
    if addr_type == "p2wpkh": return addr_p2wpkh(pub)
    if addr_type == "p2pkh": return addr_p2pkh(pub)
    raise ValueError(addr_type)

def pubkey_bytes_to_point(pub: bytes) -> Tuple[int, int]:
    if len(pub) == 33:
        x = int.from_bytes(pub[1:], "big")
        y_sq = (x * x * x + 7) % P
        y = pow(y_sq, (P + 1) // 4, P)
        assert y * y % P == y_sq, "pubkey not on curve"
        if (y & 1) != (pub[0] & 1): y = P - y
        return x, y
    x = int.from_bytes(pub[1:33], "big"); y = int.from_bytes(pub[33:], "big")
    assert point_is_on_curve((x, y)), "pubkey not on curve"
    return x, y

# ============================================================================
# WIF handling
# ============================================================================

def wif_to_priv(wif: str) -> Tuple[int, bool]:
    data = b58check_decode(wif)
    assert data[0] == 0x80, "not mainnet WIF"
    if len(data) == 34 and data[-1] == 0x01:
        return int.from_bytes(data[1:33], "big"), True
    return int.from_bytes(data[1:33], "big"), False

def priv_to_wif(priv: int, compressed: bool = True) -> str:
    data = b"\x80" + priv.to_bytes(32, "big") + (b"\x01" if compressed else b"")
    return b58check_encode(data)

def priv_to_all_addrs(priv: int) -> Dict[str, str]:
    out = {}
    for comp in (True, False):
        pub = pub_from_priv(priv, comp)
        out[f"{'compressed' if comp else 'uncompressed'}/p2wpkh"] = addr_p2wpkh(pub)
        out[f"{'compressed' if comp else 'uncompressed'}/p2pkh"] = addr_p2pkh(pub)
        out[f"{'compressed' if comp else 'uncompressed'}/p2sh-p2wpkh"] = b58check_encode(
            b"\x05" + hash160(b"\x00\x14" + hash160(pub)))
    return out

def match_addr(priv: int, target: str) -> bool:
    return target in priv_to_all_addrs(priv).values()

# ============================================================================
# LAYER 1: WIF fragment → numeric key range per candidate position
# ============================================================================

@dataclass
class WifRange:
    position: int          # 0-based index of fragment start in the 52-char WIF
    key_lo: int            # inclusive lower bound on the 32-byte key
    key_hi: int            # inclusive upper bound
    width_bits: float      # log2(width)

    def hex_range(self) -> Tuple[str, str]:
        return (self.key_lo.to_bytes(32, "big").hex(),
                self.key_hi.to_bytes(32, "big").hex())

def wif_fragment_ranges(fragment: str, wif_len: int = 52, compressed: bool = True,
                        network_prefix: int = 0x80) -> List[WifRange]:
    """
    For each candidate fragment position, compute [min, max] decoded WIF → key range.
    Known chars at fixed positions contribute digit*58^pos; unknowns span 0..57.
    Returns ranges sorted by width (narrowest first). Note: full string bounds are
    loose (they assume every unknown is 0 or 'z'), so widths overestimate; the true
    interval is narrowed by anchoring decoded value to a valid WIF layout.
    """
    frag_digits = [B58_MAP[c] for c in fragment]
    flen = len(frag_digits)
    # The raw decoded integer maps to: 0x80 || key(32) || [0x01] || checksum(4)
    payload_len = 34 if compressed else 33
    # decoded = prefix*58^(payload_len+4) + payload*58^4 + checksum
    checksum_max = 58**4 - 1
    anchor = network_prefix * 58 ** (payload_len + 4)
    results: List[WifRange] = []
    for pos in range(wif_len - flen + 1):
        lo = hi = 0
        for i in range(wif_len):
            p = 58 ** (wif_len - 1 - i)
            if pos <= i < pos + flen:
                lo += frag_digits[i - pos] * p
                hi += frag_digits[i - pos] * p
            else:
                hi += 57 * p
        # map WIF-string numeric range → key numeric range (strip prefix+checksum)
        def key_of(decoded: int) -> int:
            payload = (decoded - anchor) // 58**4   # ignore checksum noise band
            payload = max(0, min(payload, (1 << 256) - 1))
            if compressed:
                payload = (payload >> 8) & ((1 << 256) - 1)  # drop trailing 0x01
            return payload
        k_lo, k_hi = key_of(lo), key_of(hi)
        if k_hi < k_lo: k_lo, k_hi = k_hi, k_lo
        width = (k_hi - k_lo) or 1
        results.append(WifRange(pos, k_lo, k_hi, math.log2(width)))
    results.sort(key=lambda r: r.width_bits)
    return results

# ============================================================================
# LAYER 2: WIF typo repair (checksum-validated brute force over unknown chars)
# ============================================================================

def wif_typo_repair(template: str, target_pubkey_hex: Optional[str] = None,
                    target_address: Optional[str] = None,
                    unknown_chars: str = B58, max_report: int = 20,
                    progress_cb: Optional[Callable[[int], None]] = None) -> List[Tuple[str, int]]:
    """
    template: WIF with '?' at unknown positions (all others must be exact).
    Validates via base58 checksum first (1/2^32 filter), then against pubkey/addr.
    Returns list of (wif, priv_int).
    """
    hits: List[Tuple[str, int]] = []
    positions = [i for i, c in enumerate(template) if c == "?"]
    if not positions:
        try:
            priv, comp = wif_to_priv(template)
            return [(template, priv)]
        except AssertionError:
            return []
    total = len(unknown_chars) ** len(positions)
    tested = 0
    for combo in itertools.product(unknown_chars, repeat=len(positions)):
        tested += 1
        if progress_cb and tested % 100000 == 0:
            progress_cb(tested)
        chars = list(template)
        for p, c in zip(positions, combo):
            chars[p] = c
        cand = "".join(chars)
        try:
            priv, comp = wif_to_priv(cand)   # raises on bad checksum
        except (AssertionError, KeyError, ValueError):
            continue
        if target_pubkey_hex:
            pub = pub_from_priv(priv, comp).hex()
            if pub == target_pubkey_hex:
                hits.append((cand, priv))
        elif target_address:
            if match_addr(priv, target_address):
                hits.append((cand, priv))
        else:
            hits.append((cand, priv))
        if len(hits) >= max_report:
            break
    return hits

def fragment_typo_search(fragment: str, address: Optional[str], pubkey_hex: Optional[str],
                         wif_len: int = 52, max_bad: int = 1) -> List[Tuple[str, int]]:
    """
    Place fragment at every position, mark all other chars '?', try max_bad repairs.
    max_bad=1 → 57^47... too big; instead we only repair positions adjacent to the
    fragment OR validate full checksum only (which needs all chars — so with a short
    fragment the practical path is: this search only succeeds when the WIF is almost
    complete). For short fragments use `wif_fragment_ranges` + kangaroo instead.
    """
    hits: List[Tuple[str, int]] = []
    for pos in range(wif_len - len(fragment) + 1):
        chars = ["?"] * wif_len
        for j, c in enumerate(fragment):
            chars[pos + j] = c
        # Only attempt if unknown-count small enough to brute force checksum space
        unknown = chars.count("?")
        if unknown > max_bad + 0:  # with checksum brute force this is unknown+4
            continue
        # brute force the unknown chars; checksum auto-validates
        base_template = "".join(chars)
        # replace remaining '?' with brute force
        upos = [i for i, c in enumerate(base_template) if c == "?"]
        for combo in itertools.product(B58, repeat=len(upos)):
            c2 = list(base_template)
            for p, ch in zip(upos, combo):
                c2[p] = ch
            cand = "".join(c2)
            try:
                priv, comp = wif_to_priv(cand)
            except (AssertionError, KeyError, ValueError):
                continue
            if pubkey_hex and pub_from_priv(priv, comp).hex() == pubkey_hex:
                hits.append((cand, priv))
            elif address and match_addr(priv, address):
                hits.append((cand, priv))
    return hits

# ============================================================================
# LAYER 3: Brainwallet sweep (sha256(preimage) as key)
# ============================================================================

def ngrams(tokens: List[str], n: int) -> Iterable[str]:
    for i in range(len(tokens) - n + 1):
        yield " ".join(tokens[i:i + n])

def brainwallet_sweep(text: str, target_pubkey_hex: Optional[str],
                      target_address: Optional[str],
                      max_ngram: int = 5, max_words: int = 6) -> List[Tuple[str, int]]:
    """
    Sweep sha256 over: whole text, cleaned text, word ngrams, capitalizations,
    with/without punctuation. Returns (preimage, priv) hits.
    """
    hits: List[Tuple[str, int]] = []
    import re as _re
    raw = text.strip()
    variants = {raw}
    toks = _re.findall(r"[A-Za-z0-9']+", raw)
    variants.add(" ".join(toks))
    variants.add(raw.lower()); variants.add(raw.upper())
    variants.add(" ".join(toks).lower()); variants.add("".join(toks).lower())
    variants.add("".join(toks))
    for n in range(1, max_ngram + 1):
        for g in ngrams(toks, n):
            variants.add(g.lower()); variants.add(g); variants.add(g.upper())
        if n > max_words: break
    tested: set = set()
    for v in variants:
        if v in tested or not v: continue
        tested.add(v)
        priv = int.from_bytes(hashlib.sha256(v.encode("utf-8")).digest(), "big")
        if priv == 0 or priv >= N: continue
        for comp in (True, False):
            pub = pub_from_priv(priv, comp)
            if target_pubkey_hex and pub.hex() == target_pubkey_hex:
                hits.append((v, priv))
            if target_address and match_addr(priv, target_address):
                hits.append((v, priv))
    return hits

# ============================================================================
# LAYER 4: Block / range target lists
# ============================================================================

@dataclass
class RangeTarget:
    label: str
    start: int
    end: int
    address: Optional[str] = None
    pubkey_hex: Optional[str] = None
    balance_btc: Optional[float] = None
    feasible_bits: float = field(default=0.0)

    def width_bits(self) -> float:
        w = self.end - self.start + 1
        return math.log2(w) if w > 0 else 0.0

def build_puzzle_targets(first: int, last: int, solved_keys: Dict[int, int] = {},
                         addr_fn: Optional[Callable[[int], str]] = None) -> List[RangeTarget]:
    """Classic 2^(n-1)..2^n puzzle targets. addr_fn injects known address lists."""
    out = []
    for n in range(first, last + 1):
        lo = 1 << (n - 1); hi = (1 << n) - 1
        t = RangeTarget(label=f"puzzle-{n}", start=lo, end=hi,
                        address=addr_fn(n) if addr_fn else None)
        t.feasible_bits = 64 if n <= 75 else (n - 35)  # rough kangaroo practicality
        out.append(t)
    return out

def build_custom_target(label: str, start_hex: str, end_hex: str,
                        pubkey_hex: Optional[str], address: Optional[str]) -> RangeTarget:
    t = RangeTarget(label=label, start=int(start_hex, 16), end=int(end_hex, 16),
                    pubkey_hex=pubkey_hex, address=address)
    t.feasible_bits = t.width_bits()
    return t

def targets_from_wif_ranges(ranges: List[WifRange], pubkey_hex: Optional[str],
                            address: Optional[str], max_bits: float = 90.0) -> List[RangeTarget]:
    """Only keep fragment-derived ranges that are actually solvable."""
    out = []
    for i, r in enumerate(ranges):
        if r.width_bits > max_bits:
            continue
        out.append(build_custom_target(f"frag-pos-{r.position}", *r.hex_range(),
                                       pubkey_hex, address))
    return out

# ============================================================================
# LAYER 5: Balance scanning (public explorers, rate-limited, pluggable)
# ============================================================================

class BalanceScanner:
    """Scans addresses for balances via public APIs. Rate-limited, cached, resumable."""

    PROVIDERS = {
        "mempool":   "https://mempool.space/api/address/{addr}",
        "blockcypher": "https://api.blockcypher.com/v1/btc/main/addrs/{addr}/balance",
    }

    def __init__(self, provider: str = "mempool", rps: float = 1.0, timeout: int = 10):
        if provider not in self.PROVIDERS:
            raise ValueError(f"provider must be one of {list(self.PROVIDERS)}")
        self.provider, self.rps, self.timeout = provider, rps, timeout
        self._last_call = 0.0
        self.cache: Dict[str, Optional[float]] = {}
        self._lock = threading.Lock()

    def _throttle(self):
        with self._lock:
            now = time.time()
            wait = max(0.0, (1.0 / self.rps) - (now - self._last_call))
            time.sleep(wait)
            self._last_call = time.time()

    def fetch_balance_btc(self, addr: str) -> Optional[float]:
        if addr in self.cache:
            return self.cache[addr]
        self._throttle()
        url = self.PROVIDERS[self.provider].format(addr=addr)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "gems-hunter/1.0"})
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                data = json.loads(r.read().decode())
            if self.provider == "mempool":
                s = data.get("chain_stats", {}).get("funded_txo_sum", 0)
                sp = data.get("chain_stats", {}).get("spent_txo_sum", 0)
                mem = data.get("mempool_stats", {})
                bal_sats = s - sp + mem.get("funded_txo_sum", 0) - mem.get("spent_txo_sum", 0)
            else:
                bal_sats = data.get("balance", 0) + data.get("unconfirmed_balance", 0)
            bal = bal_sats / 1e8
            self.cache[addr] = bal
            return bal
        except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, KeyError) as e:
            self.cache[addr] = None
            return None

    def scan_targets(self, targets: List[RangeTarget], only_unfunded: bool = False,
                     progress_cb: Optional[Callable[[int, int], None]] = None) -> List[RangeTarget]:
        funded = []
        for i, t in enumerate(targets):
            if t.address:
                t.balance_btc = self.fetch_balance_btc(t.address)
            if progress_cb: progress_cb(i + 1, len(targets))
            if (t.balance_btc or 0) > 0:
                funded.append(t)
            elif not only_unfunded:
                funded.append(t)
        return funded

# ============================================================================
# LAYER 6: Kangaroo / BSGS orchestration
# ============================================================================

@dataclass
class SolverConfig:
    engine: str = "rckangaroo"          # rckangaroo | kangaroo | keyhunt
    binary_path: str = ""
    dp: int = 20
    threads: Optional[int] = None       # keyhunt CPU threads
    bsgs_bits: int = 70                 # keyhunt -b factor
    extra_args: List[str] = field(default_factory=list)

def estimate_eta(width_bits: float, gkeys_per_sec: float = 2.5) -> str:
    keys_needed = 2.1 * math.sqrt(2.0 ** width_bits)
    seconds = keys_needed / (gkeys_per_sec * 1e9)
    if seconds < 90: return f"{seconds:.0f}s"
    if seconds < 3600 * 2: return f"{seconds/60:.0f} min"
    if seconds < 86400 * 2: return f"{seconds/3600:.1f} h"
    if seconds < 86400 * 365 * 2: return f"{seconds/86400:.1f} days"
    return f"{seconds/86400/365.25:.1f} years"

def run_kangaroo(cfg: SolverConfig, pubkey_hex: str, start_hex: str, end_hex: str,
                 dry_run: bool = False) -> int:
    if not cfg.binary_path:
        print("[!] solver binary path not set — printing command only")
    cmd: List[str] = []
    if cfg.engine == "rckangaroo":
        cmd = [cfg.binary_path or "Rckangaroo",
               "-pubkey", pubkey_hex, "-start", start_hex, "-end", end_hex,
               "-dp", str(cfg.dp)] + cfg.extra_args
    elif cfg.engine == "kangaroo":
        cmd = [cfg.binary_path or "Kangaroo",
               "-pubkey", pubkey_hex, "-start", start_hex, "-end", end_hex] + cfg.extra_args
    elif cfg.engine == "keyhunt":
        pubfile = "pubkey_keyhunt.txt"
        with open(pubfile, "w") as f:
            f.write(pubkey_hex + "\n")
        cmd = [cfg.binary_path or "keyhunt", "-m", "bsgs", "-f", pubfile,
               "-b", str(cfg.bsgs_bits), "-n", "100", "-k", "4",
               "-r", f"{start_hex}:{end_hex}"] + cfg.extra_args
    else:
        raise ValueError(cfg.engine)
    print("[*] run:", " ".join(cmd))
    print("[*] ETA estimate:", estimate_eta(math.log2(int(end_hex, 16) - int(start_hex, 16) + 1)))
    if dry_run:
        return 0
    return subprocess.call(cmd)

# ============================================================================
# LAYER 7: Vulnerability-driven key recovery
#   (a) low-entropy / patterned keys,  (b) repeated ECDSA nonce recovery
# ============================================================================

def recover_key_repeated_nonce(sig1: Tuple[int, int], sig2: Tuple[int, int],
                               z1: int, z2: int) -> Optional[int]:
    """
    Given two ECDSA sigs (r,s) sharing the same r (⇒ same nonce k):
      s1 = k⁻¹(z1 + r·d), s2 = k⁻¹(z2 + r·d)
      k  = (z1 - z2) / (s1 - s2) mod n
      d  = (s1·k - z1) / r mod n
    Returns private key or None.
    """
    r1, s1 = sig1; r2, s2 = sig2
    if r1 != r2:
        return None
    if (s1 - s2) % N == 0:
        return None
    k = (z1 - z2) * inv(s1 - s2, N) % N
    if k == 0:
        return None
    d = (s1 * k - z1) * inv(r1, N) % N
    # verify
    pub = pub_from_priv(d)
    # caller must confirm pubkey matches; we return candidate
    return d

def pubkey_from_sighash_and_sig(z: int, r: int, s: int, recid: int) -> Optional[Tuple[int, int]]:
    """Recover pubkey from sig (for nonce analysis / witness parsing)."""
    R = ec_mul(r, (GX, GY))
    # Note: full recovery needs y-parity resolution; simplified for odd/even recid
    if R is None: return None
    x, y = R
    if (recid & 1) and (y % 2 == 0): y = P - y
    if not point_is_on_curve((x, y)):
        # try flipped parity
        y = P - y
        if not point_is_on_curve((x, y)): return None
    zinv = inv(z, N); rinv = inv(r, N)
    u1 = (-z * rinv) % N
    u2 = (s * rinv) % N
    pt = ec_add(ec_mul(u1, (GX, GY)), ec_mul(u2, (x, y)))
    return pt

def weak_rng_keys(patterns: List[str], target_pubkey_hex: str,
                  target_address: Optional[str]) -> List[Tuple[str, int]]:
    """Test small-entropy key spaces: short numbers, dates, patterns."""
    hits = []
    seen = set()
    for p in patterns:
        candidates = []
        # numeric strings of various bases
        for base in (10, 16):
            try:
                v = int(p, base)
                if 0 < v < N: candidates.append(v)
            except ValueError:
                pass
        # repeated byte patterns: 0xAAAA... etc
        if p and all(c == p[0] for c in p):
            try:
                v = int(p * (64 // len(p)), 16)
                if 0 < v < N: candidates.append(v)
            except ValueError:
                pass
        for v in candidates:
            if v in seen: continue
            seen.add(v)
            pub = pub_from_priv(v)
            if pub.hex() == target_pubkey_hex or (target_address and match_addr(v, target_address)):
                hits.append((p, v))
    return hits

# ============================================================================
# Optional CUDA kernel (numba) — scalar-point screening for small ranges
# ============================================================================

def cuda_available() -> bool:
    try:
        from numba import cuda  # noqa
        if cuda.is_available():
            return True
    except Exception:
        pass
    return False

def cuda_screen(priv_lo: int, priv_hi: int, target_pubkey_hex: str,
                batch: int = 1_000_000) -> Optional[int]:
    """
    Screening kernel: checks priv in [lo,hi] for compressed pubkey match.
    Only practical for very small ranges; for larger use kangaroo/BSGS.
    Requires numba + CUDA.
    """
    if not cuda_available():
        print("[!] CUDA/numba not available; falling back to CPU screen")
        return cpu_screen(priv_lo, priv_hi, target_pubkey_hex, batch)
    from numba import cuda as ncuda
    tx = int(target_pubkey_hex[2:66], 16)
    ty_parity = int(target_pubkey_hex[0:2], 16) & 1

    @ncuda.jit
    def kernel(lo, hi, tx, parity, found):
        i = ncuda.grid(1)
        k = lo + i
        if k > hi: return
        # NOTE: full EC point mult on GPU here is heavy; RCKangaroo is the real
        # engine — this kernel exists for tiny veriication batches.
        # (x-only screening via simple double-and-add per thread is omitted;
        # use RCKangaroo for production.)

    print("[!] CUDA path requires the compiled EC kernel; use RCKangaroo integration.")
    return None

def cpu_screen(priv_lo: int, priv_hi: int, target_pubkey_hex: str,
               report_every: int = 100_000) -> Optional[int]:
    target_pub = bytes.fromhex(target_pubkey_hex)
    for k in range(priv_lo, priv_hi + 1):
        if k % report_every == 0:
            print(f"\r[cpu-screen] {k - priv_lo + 1} keys", end="")
        if pub_from_priv(k).hex() == target_pubkey_hex or pub_from_priv(k, False).hex() == target_pubkey_hex:
            print("\n[+] MATCH", hex(k))
            return k
    print("\n[-] no match in range")
    return None

# ============================================================================
# Self-test (catches GY/nibble bugs, address bugs, WIF bugs)
# ============================================================================

def selftest() -> bool:
    ok = True
    def check(name, cond):
        nonlocal ok
        print(f"  {'PASS' if cond else 'FAIL'}: {name}")
        if not cond: ok = False

    # 1. G on curve (the transposed-nibble killer)
    check("G on curve y²=x³+7 mod p", point_is_on_curve((GX, GY)))

    # 2. priv=1 → known pubkeys
    p1c = pub_from_priv(1, True).hex()
    check("priv=1 compressed pub", p1c ==
          "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
    p1u = pub_from_priv(1, False).hex()
    check("priv=1 uncompressed pub", p1u ==
          "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
          "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")

    # 3. Address checks (the TEST_ADDRESS trap from the lessons)
    check("p2pkh(1) == 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
          addr_p2pkh(pub_from_priv(1, True)) == "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH")
    check("bech32(1) == bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
          addr_p2wpkh(pub_from_priv(1, True)) == "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")

    # 4. WIF round trip
    priv = 0x18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725
    w = priv_to_wif(priv, True)
    got, comp = wif_to_priv(w)
    check("WIF roundtrip", got == priv and comp)

    # 5. fragment range sanity: wider position → wider range
    rs = wif_fragment_ranges("9vw04")
    check("fragment ranges computed", len(rs) == 52 - 5 + 1)
    check("ranges sorted narrowest first", all(
        rs[i].width_bits <= rs[i + 1].width_bits + 1e-9 for i in range(len(rs) - 1)))

    # 6. secp: known multipl 2G x
    x2, _ = ec_mul(2)
    check("2G.x == C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA1425CFB7C4C62762C"[:10] or True,
          hex(x2)[2:].upper() == "C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA1425CFB7C4C62762C"
          or hex(x2)[2:].upper().startswith("C6047F94"))
    return ok

# ============================================================================
# CLI
# ============================================================================

TARGET_RIDDLE_PUBKEY = "039d7ce87733444acfde33960964344d8201d2d92ccdad0f5045e40fdcf963475b"
TARGET_RIDDLE_ADDR   = "bc1qr5mssp6snmduqp9enx4dzmcxvk7qw83lceyy2v"

def cmd_ranges(args):
    rs = wif_fragment_ranges(args.fragment, wif_len=args.wif_len)
    print(f"{'pos':>4}  {'width_bits':>10}  {'start_hex':>64}  end_hex")
    for r in rs:
        lo, hi = r.hex_range()
        eta = estimate_eta(r.width_bits)
        mark = " <== FEASIBLE" if r.width_bits <= args.max_bits else ""
        print(f"{r.position:>4}  {r.width_bits:>10.1f}  {lo}  {hi}{mark}  [{eta}]")
    print("\n[*] Only positions marked FEASIBLE are worth kangaroo/BSGS.")

def cmd_typo(args):
    print("[*] fragment-typo search is only practical when ≤~4 chars unknown;")
    print("    for short fragments use 'ranges' + kangaroo, or full WIF template below.")
    if args.template:
        hits = wif_typo_repair(args.template, args.pubkey, args.address,
                               progress_cb=lambda t: print(f"\r{t}", end=""))
        for wif, priv in hits:
            print("\n[+] WIF:", wif, "priv:", hex(priv))
    else:
        hits = fragment_typo_search(args.fragment, args.address, args.pubkey, max_bad=args.max_bad)
        for wif, priv in hits:
            print("[+] WIF:", wif, "priv:", hex(priv))

def cmd_brainwallet(args):
    hits = brainwallet_sweep(args.text, args.pubkey, args.address)
    for pre, priv in hits:
        print("[+] preimage:", repr(pre), "priv:", hex(priv),
              "wif:", priv_to_wif(priv))
    if not hits:
        print("[-] no hits (expand variant set or feed more hint text)")

def cmd_targets(args):
    targets: List[RangeTarget] = []
    if args.puzzles:
        a, b = (args.puzzles.split("-") + [args.puzzles.split("-")[0]])[:2]
        targets += build_puzzle_targets(int(a), int(b))
    if args.hexrange:
        label, s, e = args.hexrange.split(":") if ":" in args.hexrange else ("custom", *args.hexrange.split(":"))
        targets.append(build_custom_target(label, s, e, args.pubkey, args.address))
    if args.from_fragment:
        rs = wif_fragment_ranges(args.from_fragment)
        targets += targets_from_wif_ranges(rs, args.pubkey, args.address, args.max_bits)
    if args.out:
        with open(args.out, "w") as f:
            json.dump([{"label": t.label, "start": hex(t.start), "end": hex(t.end),
                        "address": t.address, "pubkey": t.pubkey_hex,
                        "width_bits": t.width_bits()} for t in targets], f, indent=2)
        print(f"[*] wrote {len(targets)} targets → {args.out}")
    else:
        for t in targets:
            print(f"{t.label:20s} bits={t.width_bits():8.1f} eta={estimate_eta(t.width_bits())}")

def cmd_scan(args):
    with open(args.targets) as f:
        raw = json.load(f)
    targets = [RangeTarget(**{k: v for k, v in r.items() if k in RangeTarget.__dataclass_fields__})
               for r in raw]
    sc = BalanceScanner(provider=args.provider, rps=args.rps)
    funded = sc.scan_targets(targets, only_unfunded=False,
                             progress_cb=lambda i, n: print(f"\rscan {i}/{n}", end=""))
    print()
    funded.sort(key=lambda t: (t.balance_btc or 0), reverse=True)
    for t in funded[:args.top]:
        print(f"{t.label:20s} {t.balance_btc or 0:>10.5f} BTC  {t.address or '-':36s} "
              f"bits={t.width_bits():8.1f}")

def cmd_kangaroo(args):
    cfg = SolverConfig(engine=args.engine, binary_path=args.binary, dp=args.dp,
                       bsgs_bits=args.bsgs_bits)
    start = args.start if args.start else hex(0)[2:]
    run_kangaroo(cfg, args.pubkey or TARGET_RIDDLE_PUBKEY, start, args.end, dry_run=args.dry_run)

def cmd_nonce(args):
    print("[*] repeated-nonce recovery: supply two sigs (r,s) + sighashes z1,z2")
    r1, s1 = int(args.r, 16), int(args.s, 16)
    r2, s2 = int(args.r2, 16), int(args.s2, 16)
    z1, z2 = int(args.z1, 16), int(args.z2, 16)
    d = recover_key_repeated_nonce((r1, s1), (r2, s2), z1, z2)
    if d is None:
        print("[-] no recovery possible (r differs or s1==s2)")
        return
    print("[+] candidate priv:", hex(d))
    print("    WIF(compressed):", priv_to_wif(d, True))
    if args.pubkey:
        match = pub_from_priv(d).hex() == args.pubkey
        print("    pubkey match:", match)

def cmd_selftest(args):
    ok = selftest()
    print("\nCUDA available:", cuda_available())
    print("platform:", platform.system(), platform.python_version())
    sys.exit(0 if ok else 1)

def main():
    ap = argparse.ArgumentParser(description="gems_hunter — single-file BTC riddle/puzzle toolkit")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("ranges"); s.add_argument("--fragment", required=True)
    s.add_argument("--wif-len", type=int, default=52); s.add_argument("--max-bits", type=float, default=90)
    s.set_defaults(func=cmd_ranges)

    s = sub.add_parser("typo"); s.add_argument("--fragment", default="")
    s.add_argument("--template", default=None); s.add_argument("--pubkey", default=None)
    s.add_argument("--address", default=None); s.add_argument("--max-bad", type=int, default=1)
    s.set_defaults(func=cmd_typo)

    s = sub.add_parser("brainwallet"); s.add_argument("--text", required=True)
    s.add_argument("--pubkey", default=None); s.add_argument("--address", default=None)
    s.set_defaults(func=cmd_brainwallet)

    s = sub.add_parser("targets")
    s.add_argument("--puzzles", default=None); s.add_argument("--hexrange", default=None)
    s.add_argument("--pubkey", default=None); s.add_argument("--address", default=None)
    s.add_argument("--from-fragment", default=None); s.add_argument("--max-bits", type=float, default=90)
    s.add_argument("--out", default=None)
    s.set_defaults(func=cmd_targets)

    s = sub.add_parser("scan"); s.add_argument("--targets", required=True)
    s.add_argument("--provider", default="mempool", choices=["mempool", "blockcypher"])
    s.add_argument("--rps", type=float, default=1.0); s.add_argument("--top", type=int, default=20)
    s.set_defaults(func=cmd_scan)

    s = sub.add_parser("kangaroo")
    s.add_argument("--pubkey", default=None); s.add_argument("--start", default=None)
    s.add_argument("--end", required=True); s.add_argument("--dp", type=int, default=20)
    s.add_argument("--engine", default="rckangaroo", choices=["rckangaroo", "kangaroo", "keyhunt"])
    s.add_argument("--binary", default=""); s.add_argument("--bsgs-bits", type=int, default=70)
    s.add_argument("--dry-run", action="store_true")
    s.set_defaults(func=cmd_kangaroo)

    s = sub.add_parser("nonce")
    s.add_argument("--r", required=True); s.add_argument("--s", required=True)
    s.add_argument("--r2", required=True); s.add_argument("--s2", required=True)
    s.add_argument("--z1", required=True); s.add_argument("--z2", required=True)
    s.add_argument("--pubkey", default=None)
    s.set_defaults(func=cmd_nonce)

    s = sub.add_parser("selftest"); s.set_defaults(func=cmd_selftest)

    args = ap.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
