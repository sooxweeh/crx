#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
combined_toolkit.py  --  offline Bitcoin audit toolkit + cross-platform supervisor
================================================================================
One file. Pure Python stdlib. Windows / macOS / Linux.

TOOLKIT COMMANDS (default)
  derive          derive one address from a seed
  watch-scan      match derived addresses against a target list YOU control
  utxo-analyze    summarize a supplied UTXO set
  nonce-report    report duplicate r values in a supplied signature set
  sweep-build     build an unsigned sweep tx (planning only)
  multisig        build a BIP67-sorted multisig redeem script
  tapleaf         compute a tapleaf hash and optional control block
  classify        classify an address
  selftest        run the toolkit selftest

SUPERVISOR COMMANDS (prefix with "deploy")
  deploy install     register auto-start AND start now
  deploy uninstall   remove auto-start AND stop
  deploy start       launch supervisor in background now
  deploy stop        stop supervisor + child
  deploy restart     stop then start
  deploy status      supervisor + child state
  deploy logs        tail deploy.out + sniper.out
  deploy run         foreground supervisor (what autostart calls)
  deploy selftest    environment / path / permissions check
  deploy fetch URL   download the supervised script if missing

The supervised script name is configurable via --sniper; the default is
puzzle_sniper.py. This file does not provide or vouch for that script.
"""

import argparse
import csv
import datetime as _dt
import hashlib
import hmac
import json
import os
import platform
import shutil
import signal
import struct
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

# =============================================================================
# SECTION 1  --  BITCOIN AUDIT TOOLKIT
# =============================================================================

# ---- secp256k1 -------------------------------------------------------------
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (55066263022277343669578718895168534326250603453777594175500187360389116729240,
     32670510020758816978083085130507043184471273380659243275938904335757337482424)

def _inv(a, m=P): return pow(a % m, -1, m)

def _add(A, B):
    if A is None: return B
    if B is None: return A
    x1, y1 = A; x2, y2 = B
    if x1 == x2 and (y1 + y2) % P == 0: return None
    s = ((3 * x1 * x1) * _inv(2 * y1) if A == B else (y2 - y1) * _inv(x2 - x1)) % P
    x = (s * s - x1 - x2) % P
    return x, (s * (x1 - x) - y1) % P

def _mul(k, A=G):
    k %= N; R = None
    while k:
        if k & 1: R = _add(R, A)
        A = _add(A, A); k >>= 1
    return R

def pub(k, comp=True):
    x, y = _mul(k)
    if comp: return bytes([2 | (y & 1)]) + x.to_bytes(32, "big")
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")

def lift_x(x):
    if x >= P: raise ValueError("x out of range")
    y_sq = (pow(x, 3, P) + 7) % P
    y = pow(y_sq, (P + 1) // 4, P)
    if (y * y) % P != y_sq: raise ValueError("not on curve")
    return (x, y if y % 2 == 0 else P - y)

# ---- hashes ---------------------------------------------------------------
def sha256(b):  return hashlib.sha256(b).digest()
def hash256(b): return sha256(sha256(b))
def hmac512(k, m): return hmac.new(k, m, hashlib.sha512).digest()

def _ripemd160_py(data):
    MASK32 = 0xFFFFFFFF
    def rol(x, n): return ((x << n) | (x >> (32 - n))) & MASK32
    RL = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
          7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,
          3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,
          1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,
          4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13]
    RR = [5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,
          6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,
          15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,
          8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,
          12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11]
    SL = [11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,
          7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,
          11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,
          11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,
          9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6]
    SR = [8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,
          9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,
          9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,
          15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,
          8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11]
    KL = [0x00000000,0x5A827999,0x6ED9EBA1,0x8F1BBCDC,0xA953FD4E]
    KR = [0x50A28BE6,0x5C4DD124,0x6D703EF3,0x7A6D76E9,0x00000000]
    def f(j, x, y, z):
        if j < 16:  return x ^ y ^ z
        if j < 32:  return ((x & y) | (~x & z)) & MASK32
        if j < 48:  return ((x | ~y) ^ z) & MASK32
        if j < 64:  return ((x & z) | (y & ~z)) & MASK32
        return (x ^ (y | ~z)) & MASK32
    msg = bytearray(data); bitlen = len(msg) * 8
    msg.append(0x80)
    while len(msg) % 64 != 56: msg.append(0)
    msg += struct.pack("<Q", bitlen)
    h = [0x67452301,0xEFCDAB89,0x98BADCFE,0x10325476,0xC3D2E1F0]
    for off in range(0, len(msg), 64):
        X = list(struct.unpack("<16I", msg[off:off+64]))
        al,bl,cl,dl,el = h; ar,br,cr,dr,er = h
        for j in range(80):
            rnd = j // 16
            tl = (al + f(j, bl, cl, dl) + X[RL[j]] + KL[rnd]) & MASK32
            al,el,dl,cl,bl = el,dl,rol(cl,SL[j]),bl,rol(tl,10)
            tr = (ar + f(79-j, br, cr, dr) + X[RR[j]] + KR[rnd]) & MASK32
            ar,er,dr,cr,br = er,dr,rol(cr,SR[j]),br,rol(tr,10)
        t = (h[1] + cl + dr) & MASK32
        h[1] = (h[2] + dl + er) & MASK32
        h[2] = (h[3] + el + ar) & MASK32
        h[3] = (h[4] + al + br) & MASK32
        h[4] = (h[0] + bl + cr) & MASK32
        h[0] = t
    return struct.pack("<5I", *h)

def ripemd160(data):
    try:
        h = hashlib.new("ripemd160"); h.update(data); return h.digest()
    except Exception:
        return _ripemd160_py(data)

def hash160(b): return ripemd160(sha256(b))

def tagged(tag, msg):
    t = sha256(tag.encode())
    return sha256(t + t + msg)

def varint(n):
    if n < 0xfd: return bytes([n])
    if n <= 0xffff: return b"\xfd" + struct.pack("<H", n)
    if n <= 0xffffffff: return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)

# ---- taproot (BIP340/341) --------------------------------------------------
def taproot_tweak(internal_xonly, merkle_root=b""):
    t = tagged("TapTweak", internal_xonly + merkle_root)
    Pint = lift_x(int.from_bytes(internal_xonly, "big"))
    Q = _add(Pint, _mul(int.from_bytes(t, "big")))
    if Q is None: raise ValueError("tweak produced point at infinity")
    return Q

def taproot_output_key(internal_xonly, merkle_root=b""):
    Q = taproot_tweak(internal_xonly, merkle_root)
    return Q[0].to_bytes(32, "big")

def tapleaf(script, leaf_version=0xc0):
    return tagged("TapLeaf", bytes([leaf_version]) + varint(len(script)) + script)

def tapbranch(a, b):
    if a > b: a, b = b, a
    return tagged("TapBranch", a + b)

def taproot_root(leaf, siblings):
    h = leaf
    for s in siblings:
        x = bytes.fromhex(s) if isinstance(s, str) else s
        h = tapbranch(h, x)
    return h

def control_block(internal_xonly, parity, merkle_root, leaf_version=0xc0):
    return bytes([(leaf_version & 0xfe) | (parity & 1)]) + internal_xonly + merkle_root

# ---- Base58Check ----------------------------------------------------------
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def b58e(b):
    n = int.from_bytes(b, "big"); s = ""
    while n:
        n, r = divmod(n, 58); s = B58[r] + s
    pad = len(b) - len(b.lstrip(b"\0"))
    return "1" * pad + s

def b58d(s):
    n = 0
    for c in s: n = n * 58 + B58.index(c)
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = len(s) - len(s.lstrip("1"))
    return b"\0" * pad + body

def b58check(version, payload):
    x = bytes([version]) + payload
    return b58e(x + hash256(x)[:4])

def b58decodecheck(s):
    x = b58d(s)
    if len(x) < 5 or hash256(x[:-4])[:4] != x[-4:]:
        raise ValueError("bad Base58Check")
    return x[0], x[1:-4]

# ---- Bech32 / Bech32m -----------------------------------------------------
CS = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def convertbits(data, frombits, tobits, pad=True):
    acc = 0; bits = 0; out = []; maxv = (1 << tobits) - 1
    for v in data:
        if v < 0 or (v >> frombits): raise ValueError("bad convertbits")
        acc = (acc << frombits) | v; bits += frombits
        while bits >= tobits:
            bits -= tobits; out.append((acc >> bits) & maxv)
    if pad and bits:
        out.append((acc << (tobits - bits)) & maxv)
    if not pad and (bits >= frombits or ((acc << (tobits - bits)) & maxv)):
        raise ValueError("bad padding")
    return out

def _bech32_polymod(vals):
    GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]; chk = 1
    for v in vals:
        top = chk >> 25; chk = ((chk & 0x1ffffff) << 5) ^ v
        for i, g in enumerate(GEN):
            if (top >> i) & 1: chk ^= g
    return chk

def _hrp_expand(h):
    return [ord(c) >> 5 for c in h] + [0] + [ord(c) & 31 for c in h]

def segwit_encode(hrp, ver, prog):
    data = [ver] + convertbits(prog, 8, 5)
    const = 1 if ver == 0 else 0x2bc830a3
    pm = _bech32_polymod(_hrp_expand(hrp) + data + [0] * 6) ^ const
    checksum = [(pm >> (5 * (5 - i))) & 31 for i in range(6)]
    return hrp + "1" + "".join(CS[x] for x in data + checksum)

def segwit_decode(a):
    if a.lower() != a and a.upper() != a: raise ValueError("mixed case")
    a = a.lower(); pos = a.rfind("1")
    if pos < 1 or pos + 7 > len(a): raise ValueError("bad bech32 length")
    hrp = a[:pos]; data = [CS.index(c) for c in a[pos + 1:]]
    pm = _bech32_polymod(_hrp_expand(hrp) + data)
    if pm == 1: spec = "bech32"
    elif pm == 0x2bc830a3: spec = "bech32m"
    else: raise ValueError("bad checksum")
    if len(data) < 7: raise ValueError("data too short")
    ver = data[0]
    prog = bytes(convertbits(data[1:-6], 5, 8, pad=False))
    if ver > 16: raise ValueError("bad witness version")
    if ver == 0 and spec != "bech32": raise ValueError("v0 must be bech32")
    if ver != 0 and spec != "bech32m": raise ValueError("v1+ must be bech32m")
    if len(prog) < 2 or len(prog) > 40: raise ValueError("bad program length")
    if ver == 0 and len(prog) not in (20, 32): raise ValueError("bad v0 length")
    return hrp, ver, prog

# ---- networks -------------------------------------------------------------
NET = {
    "bitcoin":  {"p2pkh": 0,   "p2sh": 5,   "hrp": "bc",   "coin": 0},
    "testnet":  {"p2pkh": 111, "p2sh": 196, "hrp": "tb",   "coin": 1},
    "litecoin": {"p2pkh": 48,  "p2sh": 50,  "hrp": "ltc",  "coin": 2},
    "dogecoin": {"p2pkh": 30,  "p2sh": 22,  "hrp": None,   "coin": 3},
}
PURPOSE = {"bip44": 44, "bip49": 49, "bip84": 84, "bip86": 86}

# ---- addresses ------------------------------------------------------------
def p2pkh(pubkey, net):
    return b58check(NET[net]["p2pkh"], hash160(pubkey))

def p2sh_p2wpkh(pubkey, net):
    redeem = b"\x00\x14" + hash160(pubkey)
    return b58check(NET[net]["p2sh"], hash160(redeem))

def p2wpkh(pubkey, net):
    hrp = NET[net]["hrp"]
    if not hrp: raise ValueError("%s has no segwit HRP" % net)
    return segwit_encode(hrp, 0, hash160(pubkey))

def p2tr(internal_pubkey, net, merkle_root=b""):
    hrp = NET[net]["hrp"]
    if not hrp: raise ValueError("%s has no segwit HRP" % net)
    xonly = internal_pubkey[1:33]
    out_key = taproot_output_key(xonly, merkle_root)
    return segwit_encode(hrp, 1, out_key)

def classify(addr):
    try:
        version, payload = b58decodecheck(addr)
        for n, c in NET.items():
            if version == c["p2pkh"] and len(payload) == 20:
                return {"type": "p2pkh", "network": n}
            if version == c["p2sh"] and len(payload) == 20:
                return {"type": "p2sh", "network": n}
    except ValueError:
        pass
    try:
        hrp, ver, prog = segwit_decode(addr)
        for n, c in NET.items():
            if c["hrp"] and hrp == c["hrp"]:
                if ver == 0 and len(prog) == 20: t = "p2wpkh"
                elif ver == 0 and len(prog) == 32: t = "p2wsh"
                elif ver == 1 and len(prog) == 32: t = "p2tr"
                else: t = "segwit"
                return {"type": t, "network": n}
    except ValueError:
        pass
    return {"type": "unknown", "network": None}

# ---- BIP32 ---------------------------------------------------------------
def master(seed):
    x = hmac512(b"Bitcoin seed", seed)
    k = int.from_bytes(x[:32], "big")
    if not 0 < k < N: raise ValueError("bad master key")
    return k, x[32:]

def ckd(k, c, i):
    data = (b"\x00" + k.to_bytes(32, "big") if i >= 2**31 else pub(k)) + struct.pack(">I", i)
    x = hmac512(c, data)
    z = int.from_bytes(x[:32], "big")
    if z >= N: raise ValueError("bad child tweak")
    child = (z + k) % N
    if child == 0: raise ValueError("zero child")
    return child, x[32:]

def parsepath(p):
    if p in ("m", "M"): return []
    if not p.startswith(("m/", "M/")): raise ValueError("bad path")
    out = []
    for x in p.split("/")[1:]:
        if not x: raise ValueError("empty path component")
        h = x.endswith(("'", "h", "H"))
        if h: x = x[:-1]
        out.append(int(x) + (2**31 if h else 0))
    return out

def derive(seed, path):
    k, c = master(seed)
    for i in parsepath(path): k, c = ckd(k, c, i)
    return k, c

# ---- address derivation by purpose ----------------------------------------
def address(seed, kind, net, account=0, change=0, index=0):
    path = f"m/{PURPOSE[kind]}'/{NET[net]['coin']}'/{account}'/{change}/{index}"
    k, _ = derive(seed, path)
    pk = pub(k)
    if kind == "bip44":  a = p2pkh(pk, net)
    elif kind == "bip49": a = p2sh_p2wpkh(pk, net)
    elif kind == "bip84": a = p2wpkh(pk, net)
    elif kind == "bip86": a = p2tr(pk, net)
    else: raise ValueError("unknown kind %s" % kind)
    return {"kind": kind, "path": path, "address": a, "pubkey": pk.hex()}

# ---- target list loading & scan -------------------------------------------
def targets(path):
    p = Path(path); out = set()
    if p.suffix.lower() == ".json":
        x = json.loads(p.read_text())
        rows = x.get("targets", x) if isinstance(x, dict) else x
        for r in rows:
            out.add(r if isinstance(r, str) else r.get("address", ""))
    elif p.suffix.lower() == ".csv":
        with p.open(newline="", encoding="utf8") as f:
            for r in csv.DictReader(f): out.add(r.get("address", ""))
    else:
        for r in p.read_text().splitlines():
            r = r.strip()
            if r and not r.startswith("#"):
                out.add(r.split(",")[0].strip())
    return {x for x in out if x}

def scan(seed, ts, gap, net, account):
    hits = []
    for kind in PURPOSE:
        for ch in (0, 1):
            for i in range(gap):
                x = address(seed, kind, net, account, ch, i)
                if x["address"] in ts: hits.append(x)
    return hits

# ---- UTXO -----------------------------------------------------------------
@dataclass
class UTXO:
    txid: str; vout: int; value: int
    address: str = ""; script_pubkey: str = ""; spent: bool = False

def read_utxos(path):
    p = Path(path)
    if p.suffix.lower() == ".csv":
        with p.open(newline="", encoding="utf8") as f:
            rows = list(csv.DictReader(f))
    else:
        x = json.loads(p.read_text())
        rows = x.get("utxos", x) if isinstance(x, dict) else x
    return [UTXO(str(r["txid"]), int(r["vout"]), int(r["value"]),
                 str(r.get("address", "")), str(r.get("script_pubkey", "")),
                 bool(r.get("spent", False))) for r in rows]

def balance(us, ts=None):
    ts = set(ts or [])
    a = [u for u in us if not u.spent and (not ts or u.address in ts)]
    by = {}
    for u in a: by[u.address] = by.get(u.address, 0) + u.value
    return {"records": len(us), "active": len(a),
            "sats": sum(u.value for u in a),
            "btc": sum(u.value for u in a) / 1e8,
            "by_address": by}

# ---- duplicate-r report ---------------------------------------------------
def nonce_report(records):
    groups = {}; n = 0
    for i, r in enumerate(records):
        try:
            z = int(str(r["r"]), 0)
            groups.setdefault(z, []).append(i); n += 1
        except (KeyError, ValueError):
            pass
    dups = [{"r": hex(k), "records": v} for k, v in groups.items() if len(v) > 1]
    return {"signatures_analyzed": n, "distinct_r": len(groups),
            "duplicate_r_groups": dups,
            "note": "Duplicate r is a red flag for nonce reuse. No private-key recovery is performed here."}

# ---- BIP67 multisig -------------------------------------------------------
def multisig(m, pubs):
    ps = sorted(bytes.fromhex(x) for x in pubs)
    if not 1 <= m <= len(ps) <= 16: raise ValueError("bad multisig")
    return bytes([80 + m]) + b"".join(bytes([len(x)]) + x for x in ps) + bytes([80 + len(ps), 174])

# ---- unsigned sweep (planning only) ---------------------------------------
def sweep(us, dest_script_hex, feerate=2):
    us = [u for u in us if not u.spent]
    if not us: raise ValueError("no active UTXOs")
    total = sum(u.value for u in us)
    fee = (10 + 68 * len(us) + 31) * feerate
    value = total - fee
    if value <= 0: raise ValueError("fee exceeds inputs")
    dest_script = bytes.fromhex(dest_script_hex)
    raw = struct.pack("<I", 2) + varint(len(us))
    for u in us:
        raw += bytes.fromhex(u.txid)[::-1] + struct.pack("<I", u.vout) + b"\x00" + struct.pack("<I", 0xfffffffd)
    raw += b"\x01" + struct.pack("<Q", value) + varint(len(dest_script)) + dest_script + b"\x00\x00\x00\x00"
    return {"unsigned_tx_hex": raw.hex(), "input_sats": total,
            "estimated_fee_sats": fee, "output_sats": value,
            "note": "Unsigned. Verify in your own signer before broadcasting."}

# ---- toolkit selftest -----------------------------------------------------
def toolkit_selftest():
    ok = True
    def chk(name, cond):
        nonlocal ok
        print("  [test] %-52s %s" % (name, "PASS" if cond else "FAIL"))
        if not cond: ok = False

    chk("sha256('abc')", sha256(b"abc").hex() ==
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    chk("ripemd160('')", ripemd160(b"").hex() ==
        "9c1185a5c5e9fc54612808977ee8f548b2258d31")
    chk("hash160(G)", hash160(pub(1)).hex() ==
        "751e76e8199196d454941c45d1b3a323f1433bd6")
    chk("mul(N) is None", _mul(N) is None)
    chk("base58check P2PKH", p2pkh(pub(1), "bitcoin") == "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH")
    chk("classify p2pkh", classify("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH") ==
        {"type": "p2pkh", "network": "bitcoin"})
    chk("bech32 P2WPKH vector", segwit_encode("bc", 0, hash160(pub(1))) ==
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
    chk("bech32 decode vector", segwit_decode("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4") ==
        ("bc", 0, hash160(pub(1))))
    chk("bech32m accepted", segwit_decode(
        "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0")[1] == 1)

    seed1 = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    k, c = master(seed1)
    chk("BIP32 tv1 m priv",
        k.to_bytes(32, "big").hex() == "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35")
    chk("BIP32 tv1 m chain",
        c.hex() == "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508")
    k0, c0 = ckd(k, c, 0x80000000)
    chk("BIP32 tv1 m/0' priv",
        k0.to_bytes(32, "big").hex() == "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea")
    chk("BIP32 tv1 m/0' chain",
        c0.hex() == "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141")

    seed_tr = bytes.fromhex(
        "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f"
        "09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04")
    chk("BIP44 m/44'/0'/0'/0/0",
        address(seed_tr, "bip44", "bitcoin")["address"] == "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA")
    chk("BIP49 m/49'/0'/0'/0/0 (P2SH-P2WPKH)",
        address(seed_tr, "bip49", "bitcoin")["address"] == "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf")
    chk("BIP84 m/84'/0'/0'/0/0",
        address(seed_tr, "bip84", "bitcoin")["address"] == "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu")
    chk("BIP86 m/86'/0'/0'/0/0 (Taproot)",
        address(seed_tr, "bip86", "bitcoin")["address"] == "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr")

    internal_pub_hex = bytes.fromhex(
        "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115")
    k86, _ = derive(seed_tr, "m/86'/0'/0'/0/0")
    chk("BIP86 internal key x-only",
        pub(k86)[1:].hex() == internal_pub_hex.hex())

    a = pub(secrets_k1()); b = pub(secrets_k2()); c = pub(secrets_k3())
    redeem = multisig(2, [a.hex(), b.hex(), c.hex()])
    chk("multisig OP_2 ... OP_3 OP_CHECKMULTISIG",
        redeem[0] == 0x52 and redeem[-1] == 0xae and redeem[-2] == 0x53)
    chk("BIP67 sort deterministic",
        multisig(2, [a.hex(), b.hex(), c.hex()]) ==
        multisig(2, [c.hex(), b.hex(), a.hex()]))
    leaf = tapleaf(b"\x20" + b"\x11" * 32 + b"\xac")
    chk("tapleaf 32-byte hash", len(leaf) == 32)
    cb = control_block(b"\x00" * 32, 0, leaf)
    chk("control block 33+32", len(cb) == 65)

    print("\n  %s" % ("ALL PASS" if ok else "FAILURES - do not use"))
    return ok

def secrets_k1(): return int.from_bytes(sha256(b"v5 k1"), "big") % (N - 1) + 1
def secrets_k2(): return int.from_bytes(sha256(b"v5 k2"), "big") % (N - 1) + 1
def secrets_k3(): return int.from_bytes(sha256(b"v5 k3"), "big") % (N - 1) + 1

# ---- toolkit CLI ----------------------------------------------------------
def _toolkit_main():
    p = argparse.ArgumentParser(description="BTC Toolkit - offline audit toolkit")
    s = p.add_subparsers(dest="cmd", required=True)

    q = s.add_parser("derive")
    q.add_argument("--seed-hex", required=True)
    q.add_argument("--kind", choices=PURPOSE, default="bip84")
    q.add_argument("--network", choices=NET, default="bitcoin")
    q.add_argument("--account", type=int, default=0)
    q.add_argument("--change", type=int, default=0)
    q.add_argument("--index", type=int, default=0)
    q.set_defaults(f=lambda a: print(json.dumps(
        address(bytes.fromhex(a.seed_hex), a.kind, a.network, a.account, a.change, a.index),
        indent=2)))

    q = s.add_parser("watch-scan")
    q.add_argument("--seed-hex", required=True)
    q.add_argument("--targets", required=True)
    q.add_argument("--gap", type=int, default=20)
    q.add_argument("--network", choices=NET, default="bitcoin")
    q.add_argument("--account", type=int, default=0)
    q.set_defaults(f=lambda a: print(json.dumps(
        {"hits": scan(bytes.fromhex(a.seed_hex), targets(a.targets), a.gap, a.network, a.account)},
        indent=2)))

    q = s.add_parser("utxo-analyze")
    q.add_argument("--file", required=True)
    q.add_argument("--targets")
    q.set_defaults(f=lambda a: print(json.dumps(
        balance(read_utxos(a.file), targets(a.targets) if a.targets else None), indent=2)))

    q = s.add_parser("nonce-report")
    q.add_argument("--file", required=True)
    q.set_defaults(f=lambda a: print(json.dumps(
        nonce_report(json.loads(Path(a.file).read_text()).get("signatures", [])), indent=2)))

    q = s.add_parser("sweep-build")
    q.add_argument("--utxos", required=True)
    q.add_argument("--destination-script", required=True)
    q.add_argument("--fee-rate", type=int, default=2)
    q.set_defaults(f=lambda a: print(json.dumps(
        sweep(read_utxos(a.utxos), a.destination_script, a.fee_rate), indent=2)))

    q = s.add_parser("multisig")
    q.add_argument("-m", type=int, required=True)
    q.add_argument("--pubkey", action="append", required=True)
    q.set_defaults(f=lambda a: print(json.dumps(
        {"redeem_script": multisig(a.m, a.pubkey).hex()}, indent=2)))

    q = s.add_parser("tapleaf")
    q.add_argument("--script", required=True)
    q.add_argument("--sibling", action="append", default=[])
    q.add_argument("--leaf-version", type=lambda x: int(x, 0), default=0xc0)
    q.add_argument("--internal-xonly")
    q.add_argument("--output-parity", type=int, default=0)
    q.set_defaults(f=lambda a: _cmd_tapleaf(a))

    q = s.add_parser("classify")
    q.add_argument("--address", required=True)
    q.set_defaults(f=lambda a: print(json.dumps(classify(a.address), indent=2)))

    q = s.add_parser("selftest")
    q.set_defaults(f=lambda a: sys.exit(0 if toolkit_selftest() else 1))

    a = p.parse_args()
    a.f(a)

def _cmd_tapleaf(a):
    lf = tapleaf(bytes.fromhex(a.script), a.leaf_version)
    root = taproot_root(lf, a.sibling)
    out = {"tapleaf_hash": lf.hex(), "merkle_root": root.hex()}
    if a.internal_xonly:
        out["control_block"] = control_block(
            bytes.fromhex(a.internal_xonly), a.output_parity, root, a.leaf_version).hex()
    print(json.dumps(out, indent=2))

# =============================================================================
# SECTION 2  --  DEPLOY / SUPERVISOR
# =============================================================================

IS_WIN = (os.name == "nt")
IS_MAC = (sys.platform == "darwin")
IS_LINUX = sys.platform.startswith("linux")

IDLE_PRIORITY         = 0x00000040
BELOW_NORMAL_PRIORITY = 0x00004000
NORMAL_PRIORITY       = 0x00000020

TASK_NAME    = "PuzzleSniperDeploy"
SVC_PID      = "supervisor.pid"
SVC_STATE    = "supervisor.json"
DEPLOY_OUT   = "deploy.out"
SNIPER_OUT   = "sniper.out"
LAUNCH_AGENT = "co.hackerai.puzzle_sniper.deploy.plist"
SYSTEMD_UNIT = "puzzle-sniper.service"

BACKOFF_MIN = 5
BACKOFF_MAX = 300
POLL        = 2

RUNNING = [True]
ARGS    = None
WORKDIR = None

def setup_console():
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

def log(msg):
    ts = _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = "[%s] %s" % (ts, msg)
    try:
        print(line, flush=True)
    except Exception:
        pass
    try:
        with open(os.path.join(WORKDIR or ".", DEPLOY_OUT), "a",
                  encoding="utf-8", newline="\n") as f:
            f.write(line + "\n")
    except Exception:
        pass

def write_text(path, text):
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)

def read_text(path, default=""):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception:
        return default

def pid_alive(pid):
    if not pid:
        return False
    pid = int(pid)
    if IS_WIN:
        try:
            import ctypes
            h = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)
            if not h:
                return False
            ctypes.windll.kernel32.CloseHandle(h)
            return True
        except Exception:
            return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False

def kill_pid(pid):
    pid = int(pid)
    if not pid_alive(pid):
        return False
    if IS_WIN:
        subprocess.call(["taskkill", "/PID", str(pid), "/F", "/T"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        try:
            os.kill(pid, signal.SIGTERM)
            for _ in range(10):
                if not pid_alive(pid):
                    break
                time.sleep(0.5)
            if pid_alive(pid):
                os.kill(pid, signal.SIGKILL)
        except Exception:
            pass
    return True

def state_write(child_pid, restarts, started, status):
    obj = {"supervisor_pid": os.getpid(), "child_pid": child_pid,
           "restarts": restarts, "started": started,
           "last_beat": time.time(), "status": status,
           "host": platform.node(), "platform": platform.system()}
    try:
        with open(os.path.join(WORKDIR, SVC_STATE), "w",
                  encoding="utf-8", newline="\n") as f:
            json.dump(obj, f, indent=2)
    except Exception:
        pass
    return obj

def state_read():
    try:
        with open(os.path.join(WORKDIR, SVC_STATE), encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def heartbeat_age():
    st = state_read()
    if not st.get("last_beat"):
        return None
    return time.time() - st["last_beat"]

def python_launcher(silent=True):
    py = sys.executable
    if IS_WIN and silent:
        alt = os.path.join(os.path.dirname(py), "pythonw.exe")
        if os.path.exists(alt):
            return alt
    return py

def sniper_path():
    return os.path.join(WORKDIR, ARGS.sniper)

def launch_child():
    sp = sniper_path()
    if not os.path.exists(sp):
        log("SNIPER MISSING: %s (use --fetch URL or drop the file there)" % sp)
        return None
    py = python_launcher(silent=not ARGS.console)
    cmd = [py, sp, "--no-dashboard", "--priority", ARGS.prio]
    out = open(os.path.join(WORKDIR, SNIPER_OUT), "ab")
    kw = {"cwd": WORKDIR, "stdout": out, "stderr": subprocess.STDOUT,
          "stdin": subprocess.DEVNULL}
    if IS_WIN:
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        flags |= getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        flags |= IDLE_PRIORITY if ARGS.prio == "idle" else (
            BELOW_NORMAL_PRIORITY if ARGS.prio == "below" else NORMAL_PRIORITY)
        if not ARGS.console:
            kw["creationflags"] = flags
    else:
        if hasattr(os, "nice"):
            kw["preexec_fn"] = lambda: os.nice(19)
    try:
        pr = subprocess.Popen(cmd, **kw)
    except Exception as e:
        log("spawn failed: %s" % e)
        try:
            out.close()
        except Exception:
            pass
        return None
    log("child started pid=%d cmd=%s" % (pr.pid, " ".join(cmd)))
    return pr

def _on_signal(signum, _frame):
    RUNNING[0] = False

def supervisor_loop():
    sp = os.path.join(WORKDIR, SVC_PID)
    if os.path.exists(sp):
        try:
            old = int(read_text(sp).strip())
            if old != os.getpid() and pid_alive(old):
                log("another supervisor running (pid %d) - aborting" % old)
                return 1
        except Exception:
            pass
    write_text(sp, str(os.getpid()))
    log("supervisor up pid=%d dir=%s prio=%s" % (os.getpid(), WORKDIR, ARGS.prio))

    if IS_WIN:
        for s in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(s, _on_signal)
            except Exception:
                pass
    else:
        for s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            try:
                signal.signal(s, _on_signal)
            except Exception:
                pass

    child = None
    restarts = 0
    started = time.time()
    delay = BACKOFF_MIN
    exit_code = 0

    try:
        while RUNNING[0]:
            if child is None:
                child = launch_child()
                if child is None:
                    state_write(0, restarts, started, "sniper-missing")
                    _sleep_interruptible(10)
                    continue
                state_write(child.pid, restarts, started, "running")
            rc = child.poll()
            if rc is not None:
                log("child exited rc=%s" % rc)
                child = None
                restarts += 1
                delay = min(BACKOFF_MAX, BACKOFF_MIN if restarts <= 1 else delay * 2)
                state_write(0, restarts, started, "restart-wait")
                log("restart #%d in %ds" % (restarts, delay))
                _sleep_interruptible(delay)
                continue
            state_write(child.pid, restarts, started, "running")
            _sleep_interruptible(POLL)
    finally:
        if child is not None and child.poll() is None:
            log("terminating child pid=%d" % child.pid)
            kill_pid(child.pid)
        state_write(0, restarts, started, "stopped")
        try:
            os.remove(sp)
        except Exception:
            pass
        log("supervisor down")
    return exit_code

def _sleep_interruptible(seconds):
    end = time.time() + seconds
    while RUNNING[0] and time.time() < end:
        time.sleep(min(1, max(0.05, end - time.time())))

def _self_cmd(background=False):
    py = python_launcher(silent=True) if not ARGS.console else sys.executable
    script = os.path.abspath(__file__)
    cmd = [py, script, "deploy"]
    if ARGS.dir:
        cmd += ["--dir", os.path.abspath(WORKDIR)]
    cmd += ["--prio", ARGS.prio]
    if ARGS.sniper != "puzzle_sniper.py":
        cmd += ["--sniper", ARGS.sniper]
    return cmd

def install_startup():
    cmd = _self_cmd() + ["run"]
    if IS_WIN:
        tr = subprocess.list2cmdline(cmd)
        r = subprocess.run(["schtasks", "/create", "/tn", TASK_NAME,
                            "/tr", tr, "/sc", "onlogon", "/rl", "highest", "/f"],
                           capture_output=True, text=True)
        print((r.stdout or r.stderr).strip() or "schtasks create done")
    elif IS_MAC:
        plist = os.path.expanduser("~/Library/LaunchAgents/" + LAUNCH_AGENT)
        os.makedirs(os.path.dirname(plist), exist_ok=True)
        args_xml = "".join("<string>%s</string>" % a for a in cmd)
        write_text(plist, """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>co.hackerai.puzzle_sniper.deploy</string>
  <key>ProgramArguments</key><array>%s</array>
  <key>WorkingDirectory</key><string>%s</string>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>%s</string>
  <key>StandardErrorPath</key><string>%s</string>
</dict></plist>""" % (args_xml, WORKDIR,
                     os.path.join(WORKDIR, DEPLOY_OUT),
                     os.path.join(WORKDIR, DEPLOY_OUT)))
        subprocess.call(["launchctl", "unload", plist],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.call(["launchctl", "load", plist])
        print("launchd agent installed: %s" % plist)
    else:
        unit_dir = os.path.expanduser("~/.config/systemd/user")
        unit_path = os.path.join(unit_dir, SYSTEMD_UNIT)
        have_systemd = bool(shutil.which("systemctl"))
        if have_systemd:
            os.makedirs(unit_dir, exist_ok=True)
            write_text(unit_path, """[Unit]
Description=Puzzle Sniper (supervisor)
After=network-online.target

[Service]
Type=simple
WorkingDirectory=%s
ExecStart=%s
Restart=always
RestartSec=10
Nice=19

[Install]
WantedBy=default.target
""" % (WORKDIR, subprocess.list2cmdline(cmd)))
            subprocess.call(["systemctl", "--user", "daemon-reload"])
            subprocess.call(["systemctl", "--user", "enable", "--now", SYSTEMD_UNIT])
            print("systemd user unit installed + started: %s" % unit_path)
        else:
            line = "%s >/dev/null 2>&1" % subprocess.list2cmdline(cmd)
            subprocess.run('(crontab -l 2>/dev/null; echo "@reboot %s") | crontab -'
                           % line, shell=True)
            print("crontab @reboot installed (no systemd found)")
    print("auto-start installed -> supervisor relaunches sniper on crash + reboot")

def uninstall_startup():
    if IS_WIN:
        r = subprocess.run(["schtasks", "/delete", "/tn", TASK_NAME, "/f"],
                           capture_output=True, text=True)
        print((r.stdout or r.stderr).strip() or "schtasks delete done")
    elif IS_MAC:
        plist = os.path.expanduser("~/Library/LaunchAgents/" + LAUNCH_AGENT)
        subprocess.call(["launchctl", "unload", plist])
        try:
            os.remove(plist)
            print("launchd agent removed")
        except Exception:
            print("no plist found")
    else:
        if shutil.which("systemctl"):
            subprocess.call(["systemctl", "--user", "disable", "--now", SYSTEMD_UNIT])
            try:
                os.remove(os.path.expanduser("~/.config/systemd/user/" + SYSTEMD_UNIT))
            except Exception:
                pass
            subprocess.call(["systemctl", "--user", "daemon-reload"])
            print("systemd user unit removed")
        subprocess.run('crontab -l 2>/dev/null | grep -v "deploy.py" | crontab -',
                       shell=True)
        print("crontab entry removed (if any)")

def start_bg():
    if pid_alive(int(st_read_pid() or 0)):
        print("supervisor already running (pid %s)" % st_read_pid())
        return 0
    cmd = _self_cmd() + ["run"]
    kw = {"stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL,
          "stderr": subprocess.DEVNULL, "cwd": WORKDIR}
    if IS_WIN:
        kw["creationflags"] = (getattr(subprocess, "DETACHED_PROCESS", 0) |
                               getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) |
                               getattr(subprocess, "CREATE_NO_WINDOW", 0))
        kw["close_fds"] = True
    else:
        kw["start_new_session"] = True
    subprocess.Popen(cmd, **kw)
    print("supervisor launched in background -> %s" % os.path.join(WORKDIR, SVC_STATE))
    return 0

def st_read_pid():
    sp = os.path.join(WORKDIR, SVC_PID)
    return read_text(sp).strip() or str(state_read().get("supervisor_pid") or "")

def stop_all():
    st = state_read()
    cpid = st.get("child_pid")
    if cpid:
        log("stopping child pid=%s" % cpid)
        kill_pid(cpid)
    spid = st_read_pid()
    if spid:
        log("stopping supervisor pid=%s" % spid)
        kill_pid(spid)
    try:
        os.remove(os.path.join(WORKDIR, SVC_PID))
    except Exception:
        pass
    state_write(0, st.get("restarts", 0), st.get("started", 0), "stopped")
    print("stopped (supervisor + child)")

def status():
    st = state_read()
    spid = st_read_pid()
    sup_up = pid_alive(spid) if spid else False
    cpid = st.get("child_pid") or 0
    child_up = pid_alive(cpid) if cpid else False
    age = heartbeat_age()
    print("dir          : %s" % WORKDIR)
    print("sniper file  : %s (%s)" %
          (sniper_path(), "present" if os.path.exists(sniper_path()) else "MISSING"))
    print("supervisor   : %s (pid %s)" % ("UP" if sup_up else "DOWN", spid or "-"))
    print("child sniper : %s (pid %s)" % ("UP" if child_up else "DOWN", cpid or "-"))
    print("restarts     : %s" % st.get("restarts", 0))
    print("status       : %s" % st.get("status", "-"))
    print("heartbeat    : %s" % ("%.1fs ago" % age if age is not None else "none"))
    print("platform     : %s %s" % (platform.system(), platform.release()))
    return 0

def logs():
    for name in (DEPLOY_OUT, SNIPER_OUT):
        p = os.path.join(WORKDIR, name)
        print("==== %s ====" % p)
        if not os.path.exists(p):
            print("(none)")
            continue
        try:
            with open(p, "rb") as f:
                f.seek(max(0, os.path.getsize(p) - 6000))
                tail = f.read().decode("utf-8", "replace")
            for line in tail.splitlines()[-40:]:
                print(line)
        except Exception as e:
            print("read error: %s" % e)
    return 0

def deploy_selftest():
    ok = True
    print("python     : %s" % platform.python_version())
    print("platform   : %s" % platform.system())
    print("workdir    : %s" % WORKDIR)
    ok &= os.path.isdir(WORKDIR)
    ok &= os.path.exists(sniper_path())
    print("sniper     : %s" % ("OK" if os.path.exists(sniper_path()) else "MISSING"))
    pid = os.getpid()
    ok &= pid_alive(pid)
    print("pid_alive  : %s" % ok)
    probe = os.path.join(WORKDIR, ".deploy_probe")
    try:
        write_text(probe, "x"); os.remove(probe); w_ok = True
    except Exception:
        w_ok = False
    ok &= w_ok
    print("writable   : %s" % w_ok)
    if IS_WIN:
        ok &= bool(shutil.which("schtasks"))
        print("schtasks   : %s" % bool(shutil.which("schtasks")))
    elif IS_MAC:
        ok &= bool(shutil.which("launchctl"))
        print("launchctl  : %s" % bool(shutil.which("launchctl")))
    else:
        print("systemctl  : %s" % bool(shutil.which("systemctl")))
    print("hashcat    : %s" % (shutil.which("hashcat") or "not in PATH (optional)"))
    print("SELFTEST   : %s" % ("ALL PASS" if ok else "FAILURES"))
    return 0 if ok else 1

def fetch_sniper(url):
    dest = sniper_path()
    if os.path.exists(dest):
        print("sniper already present: %s" % dest)
        return 0
    import urllib.request
    print("fetching %s" % url)
    req = urllib.request.Request(url, headers={"User-Agent": "combined/1.0"})
    with urllib.request.urlopen(req, timeout=120) as r, open(dest, "wb") as f:
        shutil.copyfileobj(r, f)
    print("wrote %s (%d bytes)" % (dest, os.path.getsize(dest)))
    return 0

def _deploy_main():
    global ARGS, WORKDIR
    ap = argparse.ArgumentParser(
        description="combined_toolkit.py deploy -- supervisor")
    ap.add_argument("command", choices=["install", "uninstall", "start", "stop",
                                        "restart", "status", "logs", "run", "selftest"])
    ap.add_argument("--dir", default="")
    ap.add_argument("--prio", choices=["idle", "below", "normal"], default="idle")
    ap.add_argument("--sniper", default="puzzle_sniper.py")
    ap.add_argument("--fetch", metavar="URL")
    ap.add_argument("--console", action="store_true")
    ARGS = ap.parse_args()

    WORKDIR = os.path.abspath(ARGS.dir) if ARGS.dir else \
        os.path.dirname(os.path.abspath(__file__))
    if not os.path.isdir(WORKDIR):
        os.makedirs(WORKDIR, exist_ok=True)
    try:
        os.chdir(WORKDIR)
    except Exception:
        pass

    setup_console()

    if ARGS.fetch:
        fetch_sniper(ARGS.fetch); sys.exit(0)

    cmd = ARGS.command
    if cmd == "selftest": sys.exit(deploy_selftest())
    if cmd == "run":      sys.exit(supervisor_loop())
    if cmd == "start":    sys.exit(start_bg())
    if cmd == "stop":     stop_all(); sys.exit(0)
    if cmd == "restart":  stop_all(); time.sleep(2); sys.exit(start_bg())
    if cmd == "status":   sys.exit(status())
    if cmd == "logs":     sys.exit(logs())
    if cmd == "install":
        install_startup()
        if not pid_alive(int(st_read_pid() or 0)):
            start_bg()
        sys.exit(0)
    if cmd == "uninstall":
        uninstall_startup(); stop_all(); sys.exit(0)
    sys.exit(0)

# =============================================================================
# SECTION 3  --  DISPATCHER
# =============================================================================

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "deploy":
        sys.argv = [sys.argv[0]] + sys.argv[2:]
        _deploy_main()
    else:
        _toolkit_main()

if __name__ == "__main__":
    main()
