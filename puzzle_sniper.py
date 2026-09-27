#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
puzzle_sniper.py  v4.2  -  WALLET RECOVERY + PUZZLE ENGINE + TELEGRAM  (stdlib only)
====================================================================================
ONE FILE. PURE PYTHON. CROSS-PLATFORM (Windows CMD / macOS / Linux).
CPU-minimal by design: IDLE process priority, supervisor poll <=2s, long-poll bot,
quiet mode, silent background daemon, auto-start, crash/stall reboot self-healing.

WHAT IT DOES
  A) WALLET RECOVERY
     --wallet-scan FILE      BDB walk: mkey/ckey/key/pkey -> addresses + hashcat 11300
     --wallet-diff A B       binary diff (Guiffy-style regions)
     --noise-scan DIR        hunt wallet.dat.bak / walletbackups\ copies
     --verify-blob           decode ASCII-decimal blob and test as private key
     --crack                 hashcat 11300 plan (Mandriana_ + digits + blob cands)
     --snipe-dat URL         download a remote wallet.dat, scan it, extract hashcat hash
     --layout-wordlist S D   RU<->EN (ЙЦУКЕН/QWERTY) mutant wordlist generator

  B) PUZZLE ENGINE (dual: Kangaroo pubkey-range + BitCrack address-range)
     monitor secretscan / btcpuzzle, queue pubkey puzzles (135/140/145/150/155/160),
     #136 address-mode, custom pubkey target. never idle, crash/stall auto-restart,
     workfile resume, boot healing, auto-resume paused after cooldown.

  C) TELEGRAM BOT (long-poll ~50s, near-zero idle CPU, FULL TAPPABLE MENU)
     /menu /close /status /queue /solved /engine /ping /restart /resume
     /add N /remove ID /addaddr ADDR BITS /range N /key ID /sweep ID /refresh
     /wallet PATH /diff A B /verifyblob /snipe URL /noise DIR /crack /crackstatus /crackstop

  D) ALWAYS-ON
     --bg  --stop  --install-startup  --uninstall-startup

NOTE ON RUNNING: this file executes on YOUR machine. It is not hosted anywhere.
"""

import argparse
import datetime as _dt
import hashlib
import hmac
import json
import os
import platform
import re
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections import deque

IS_WIN = (os.name == "nt")
IS_MAC = (sys.platform == "darwin")

# =============================================================================
#  secp256k1 / bitcoin constants
# =============================================================================
P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
PUZZLE_URL  = "https://secretscan.org/Bitcoin_puzzle"
PUZZLE_URL2 = "https://btcpuzzle.info/puzzle"
KANGAROO_REPO = "JeanLucPons/Kangaroo"
BITCRACK_REPO = "brichard19/BitCrack"
PUBKEY_PUZZLES = [135, 140, 145, 150, 155, 160]
PID_FILE = "puzzle_sniper.pid"
SEP = "=" * 60
IDLE_PRIORITY         = 0x00000040
BELOW_NORMAL_PRIORITY = 0x00004000
NORMAL_PRIORITY       = 0x00000020

# ---- wallet recovery defaults ------------------------------------------------
WALLET_TARGET = "18xGHNrU26w6HSCEL8DD5o1whfiDaYgp6i"
WALLET_HASH = ("$bitcoin$64$6b45588e745d8490f2432c68533407e0f2040ff12debd840270f47543ad47c16"
               "$16$0af493ab2796f208$99974$2$00$2$00")
BLOB_STR = ("051 049 051 050 051 056 049 056 050 050 053 049 052 051 052 048 054 057 054 049 "
            "056 051 053 053 056 048 053 052 050 052 050 056 056 048 051 055 051 053 056 048 "
            "055 055 049 052 051 053 052 056 051 048 050 055 051 048 056 056 050 050 048 057 "
            "049 050 048 052 049 048 051 055 049 050 056 048 057 055 050 051 049")

# the ONLY legitimate bit-range evidence = official puzzle pubkeys
KNOWN_PUZZLE_PUB = {
    130: "03633cbe3ec02b9401c5effa144c5b4d22f87940259634858fc7e59b1c09937852",
    135: "02145d2611c823a396ef6712ce0f712f09b9b4f3135e3e0aa3230fb9b6d08d1e16",
    140: "031f6a332d3c5c4f2de2378c012f429cd109ba07d69690c6c701b6bb87860d6640",
    145: "03afdda497369e219a2c1c369954a930e4d3740968e5e4352475bcffce3140dae5",
    150: "03137807790ea7dc6e97901c2bc87411f45ed74a5629315c4e4b03a0a102250c49",
    155: "035cd1854cae45391ca4ec428cc7e6c7d9984424b954209a8eea197b9e364c05f6",
    160: "02e0a8b039282faf6fe0fd769cfbc4b6b4cf8758ba68220eac420e32b91ddfa673",
}

DEFAULT_CFG = {
    "telegram_token": "8984308813:AAGe5QW3VHozfrYsX87mVCBOeWStZZfCE4Y",
    "telegram_chat_id": "",
    "poll_interval": 60,
    "payout_address": "",
    "auto_sweep": False,
    "broadcast_on_solve": False,
    "ping_minutes": 0,
    "priority": "idle",
    "sources": ["secretscan", "btcpuzzle"],
    "supervisor": {"max_restarts": 5, "restart_cooldown": 30,
                   "stall_seconds": 180, "auto_resume_after": 600},
    "engines": {"kangaroo": {"auto_download": True, "gpu": True, "gpu_id": 0,
                             "dpbits": 26, "cpu_threads": 4},
                "bitcrack": {"auto_download": True, "compressed": True,
                             "uncompressed": False}},
    "snipe": {"auto_add_pubkey_puzzles": True, "min_bits": 40, "max_bits": 160,
              "max_queue": 8},
    "wallet": {"target_address": WALLET_TARGET, "prefix": "Mandriana_",
               "max_digits": 10, "hashcat": True},
    "targets": [
        {"id": "p136", "mode": "bitcrack", "bits": 136, "value": 13.6,
         "address": "1UDHPdovvR985NrWSkdWQDEQ1xuRiTALq", "label": "Puzzle #136"},
        {"id": "custom", "mode": "kangaroo", "bits": 136, "value": 0.0,
         "pubkey": "0256d05908226e6c1e303f0a5b9b8ebc76ec7cbf9b054bb8b95570081d6364bf63",
         "address": "bc1qgr8lqk34jkd533gp5vkscs6v3wm5va66twhuulct65necxh6gtgqmlkac7",
         "label": "custom pubkey"}
    ],
}

# =============================================================================
#  Cross-platform console setup (call once, before anything prints)
# =============================================================================
def setup_console():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

# =============================================================================
#  RIPEMD160 (pure python; self-test at import)
# =============================================================================
def _rol(x, n): return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF
_F = [lambda x,y,z: x^y^z, lambda x,y,z: (x&y)|(~x&z), lambda x,y,z: (x|~y)^z,
      lambda x,y,z: (x&z)|(y&~z), lambda x,y,z: x^(y|~z)]
_K  = [0x00000000,0x5A827999,0x6ED9EBA1,0x8F1BBCDC,0xA953FD4E]
_Kp = [0x50A28BE6,0x5C4DD124,0x6D703EF3,0x7A6D76E9,0x00000000]
_R1 = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,
       3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,
       4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13]
_R2 = [5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,
       15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,
       12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11]
_S1 = [11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,
       11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,
       9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6]
_S2 = [8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,
       9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,
       8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11]

def _ripemd160(msg):
    ml = len(msg) * 8
    msg += b"\x80"
    while len(msg) % 64 != 56: msg += b"\x00"
    msg += ml.to_bytes(8, "little")
    h = [0x67452301,0xEFCDAB89,0x98BADCFE,0x10325476,0xC3D2E1F0]
    for off in range(0, len(msg), 64):
        X = [int.from_bytes(msg[off+4*i:off+4*i+4], "little") for i in range(16)]
        A,B,C,D,E = h; Ap,Bp,Cp,Dp,Ep = h
        for i in range(80):
            j = i // 16
            T = (_rol((A+_F[j](B,C,D)+X[_R1[i]]+_K[j]) & 0xFFFFFFFF, _S1[i]) + E) & 0xFFFFFFFF
            A,E,D,C,B = E,D,_rol(C,10),B,T
            T = (_rol((Ap+_F[4-j](Bp,Cp,Dp)+X[_R2[i]]+_Kp[j]) & 0xFFFFFFFF, _S2[i]) + Ep) & 0xFFFFFFFF
            Ap,Ep,Dp,Cp,Bp = Ep,Dp,_rol(Cp,10),Bp,T
        t = (h[1]+C+Dp) & 0xFFFFFFFF; h[1] = (h[2]+D+Ep) & 0xFFFFFFFF
        h[2] = (h[3]+E+Ap) & 0xFFFFFFFF; h[3] = (h[4]+A+Bp) & 0xFFFFFFFF
        h[4] = (h[0]+B+Cp) & 0xFFFFFFFF; h[0] = t
    return b"".join(x.to_bytes(4, "little") for x in h)

assert _ripemd160(b"").hex() == "9c1185a5c5e9fc54612808977ee8f548b2258d31"
assert _ripemd160(b"abc").hex() == "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"

def sha256(b): return hashlib.sha256(b).digest()
def sha256d(b): return sha256(sha256(b))
def hash160(b): return _ripemd160(sha256(b))

# =============================================================================
#  base58 / bech32 / EC / keys
# =============================================================================
def b58encode(b):
    n = int.from_bytes(b, "big"); s = ""
    while n:
        n, r = divmod(n, 58); s = B58[r] + s
    return "1" * (len(b) - len(b.lstrip(b"\x00"))) + s

def b58decode(s):
    n = 0
    for c in s: n = n * 58 + B58.index(c)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\x00" * (len(s) - len(s.lstrip("1"))) + raw

def b58check_encode(payload): return b58encode(payload + sha256d(payload)[:4])

def b58check_decode(s):
    raw = b58decode(s)
    if len(raw) < 5 or sha256d(raw[:-4])[:4] != raw[-4:]: raise ValueError("bad Base58Check")
    return raw[:-4]

def hex_to_wif(h, compressed=True):
    payload = b"\x80" + bytes.fromhex(h.strip().lower().zfill(64)) + (b"\x01" if compressed else b"")
    return b58check_encode(payload)

def wif_to_hex(wif):
    raw = b58decode(wif.strip())
    if len(raw) not in (37, 38): raise ValueError("WIF length %d" % len(raw))
    payload, chk = raw[:-4], raw[-4:]
    if sha256d(payload)[:4] != chk: raise ValueError("checksum mismatch")
    if payload[0] != 0x80: raise ValueError("not mainnet BTC")
    return payload[1:33].hex()

def _inv(a, m): return pow(a, m - 2, m)

def _add(p, q):
    if p is None: return q
    if q is None: return p
    x1, y1 = p; x2, y2 = q
    if x1 == x2 and (y1 + y2) % P == 0: return None
    m = (3 * x1 * x1) * _inv(2 * y1, P) % P if p == q else (y2 - y1) * _inv(x2 - x1, P) % P
    x3 = (m * m - x1 - x2) % P
    return (x3, (m * (x1 - x3) - y1) % P)

def _mul(k, pt=(Gx, Gy)):
    k %= N; r = None; a = pt
    while k:
        if k & 1: r = _add(r, a)
        a = _add(a, a); k >>= 1
    return r

def compress(pt):
    x, y = pt
    return bytes([2 | (y & 1)]) + x.to_bytes(32, "big")

def pubkey_compressed(priv):
    d = int.from_bytes(priv, "big")
    if not 0 < d < N: raise ValueError("invalid key")
    try:
        from coincurve import PublicKey
        return PublicKey.from_valid_secret(priv).format(compressed=True)
    except Exception:
        pass
    return compress(_mul(d))

def on_curve(pub):
    pub = pub.strip().lower()
    if not re.fullmatch(r"0[23][0-9a-f]{64}", pub): return False
    x = int(pub[2:66], 16); y = int(pub[66:], 16)
    return 0 < x < P and 0 < y < P and (y * y - (x * x * x + 7)) % P == 0

def on_curve_bytes(pub):
    if len(pub) != 33 or pub[0] not in (2, 3): return False
    x = int.from_bytes(pub[1:], "big")
    if not 0 < x < P: return False
    y2 = (pow(x, 3, P) + 7) % P
    y = pow(y2, (P + 1) // 4, P)
    return (y * y) % P == y2

def bech32_polymod(vals):
    GEN = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in vals:
        b = chk >> 25; chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            if (b >> i) & 1: chk ^= GEN[i]
    return chk

def bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def bech32_decode(bech):
    if bech.lower() != bech and bech.upper() != bech: return None
    bech = bech.lower(); pos = bech.rfind("1")
    if pos < 1 or pos + 7 > len(bech): return None
    hrp = bech[:pos]
    data = [B32.find(c) for c in bech[pos + 1:]]
    if any(d < 0 for d in data): return None
    if bech32_polymod(bech32_hrp_expand(hrp) + data) != 1: return None
    return hrp, data[:-6]

def convertbits(data, f, t, pad=True):
    acc = bits = 0; ret = []; maxv = (1 << t) - 1
    for v in data:
        if v < 0 or (v >> f): return None
        acc = (acc << f) | v; bits += f
        while bits >= t:
            bits -= t; ret.append((acc >> bits) & maxv)
    if pad and bits: ret.append((acc << (t - bits)) & maxv)
    return ret

def bech32_encode(hrp, data):
    vals = bech32_hrp_expand(hrp) + data + [0] * 6
    pm = bech32_polymod(vals) ^ 1
    chk = [(pm >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(B32[d] for d in data + chk)

def derive_addresses(pub):
    h = hash160(pub)
    p2pkh  = b58check_encode(b"\x00" + h)
    p2sh   = b58check_encode(b"\x05" + hash160(b"\x00\x14" + h))
    p2wpkh = bech32_encode("bc", [0] + convertbits(h, 8, 5))
    return p2pkh, p2sh, p2wpkh

def verify_key(privhex, address):
    pub = pubkey_compressed(bytes.fromhex(privhex.zfill(64)))
    for n, a in zip(("P2PKH", "P2SH-P2WPKH", "P2WPKH"), derive_addresses(pub)):
        if a == address: return n
    return None

def addr_note(address):
    if not address: return "?"
    if address.startswith("bc1") and len(address) > 42:
        return "P2WSH (script-hash - not searchable/sweepable by pubkey engines)"
    if address.startswith("bc1"): return "P2WPKH (bech32)"
    if address.startswith("1"): return "P2PKH (legacy)"
    if address.startswith("3"): return "P2SH"
    return "?"

def wif_trace(wif):
    raw = b58decode(wif.strip()); payload, chk = raw[:-4], raw[-4:]
    return ("  [1] Base58 : %s\n  [2] Checksum: %s\n  [3] SHA256#1: %s\n"
            "  [4] SHA256#2: %s\n  [5] Prefix+key: %s (ok=%s)"
            % (raw.hex().upper(), chk.hex().upper(), sha256(payload).hex().upper(),
               sha256d(payload).hex().upper(), payload.hex().upper(),
               sha256d(payload)[:4] == chk))

# =============================================================================
#  RFC6979 ECDSA signing (pure; coincurve optional)
# =============================================================================
def _rfc6979_k(d, z):
    x = d.to_bytes(32, "big"); zv = z.to_bytes(32, "big")
    V = b"\x01" * 32; K = b"\x00" * 32
    K = hmac.new(K, V + b"\x00" + x + zv, hashlib.sha256).digest()
    V = hmac.new(K, V, hashlib.sha256).digest()
    K = hmac.new(K, V + b"\x01" + x + zv, hashlib.sha256).digest()
    V = hmac.new(K, V, hashlib.sha256).digest()
    while True:
        V = hmac.new(K, V, hashlib.sha256).digest()
        k = int.from_bytes(V, "big")
        if 1 <= k < N: return k
        K = hmac.new(K, V + b"\x00", hashlib.sha256).digest()
        V = hmac.new(K, V, hashlib.sha256).digest()

def _der(r, s):
    def enc(i):
        b = i.to_bytes((i.bit_length() + 7) // 8, "big") or b"\x00"
        if b[0] & 0x80: b = b"\x00" + b
        return b"\x02" + bytes([len(b)]) + b
    body = enc(r) + enc(s)
    return b"\x30" + bytes([len(body)]) + body

def _sign(priv, z):
    try:
        from coincurve import PrivateKey
        s65 = PrivateKey(priv).sign_recoverable(z.to_bytes(32, "big"), hasher=None)
        r = int.from_bytes(s65[:32], "big"); s = int.from_bytes(s65[32:64], "big")
        if s > N // 2: s = N - s
        return _der(r, s)
    except Exception:
        pass
    d = int.from_bytes(priv, "big")
    k = _rfc6979_k(d, z)
    x, _ = _mul(k); r = x % N
    s = (pow(k, N - 2, N) * (z + r * d)) % N
    if s > N // 2: s = N - s
    return _der(r, s)

# =============================================================================
#  Utils / config / priority / state  (cross-platform)
# =============================================================================
def log(msg):
    ts = _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = "[%s] %s" % (ts, msg)
    try: print(line, flush=True)
    except Exception: pass
    try:
        with open("app.log", "a", encoding="utf-8", newline="\n") as f:
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

def set_priority(level="idle"):
    if not IS_WIN: return
    try:
        import ctypes
        vals = {"idle": IDLE_PRIORITY, "below": BELOW_NORMAL_PRIORITY,
                "normal": NORMAL_PRIORITY}
        h = ctypes.windll.kernel32.GetCurrentProcess()
        ctypes.windll.kernel32.SetPriorityClass(h, vals.get(level, IDLE_PRIORITY))
    except Exception:
        pass

def pid_alive(pid):
    if not pid: return False
    pid = int(pid)
    if IS_WIN:
        try:
            import ctypes
            h = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)
            if not h: return False
            ctypes.windll.kernel32.CloseHandle(h)
            return True
        except Exception:
            return False
    try:
        os.kill(pid, 0); return True
    except OSError:
        return False

def kill_pid(pid):
    pid = int(pid)
    if IS_WIN:
        subprocess.call(["taskkill", "/PID", str(pid), "/F", "/T"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        try: os.kill(pid, signal.SIGTERM)
        except Exception:
            try: os.kill(pid, signal.SIGKILL)
            except Exception: pass

def cfg_load():
    if os.path.exists("config.json"):
        try:
            with open("config.json", encoding="utf-8") as f: cfg = json.load(f)
        except Exception:
            cfg = {}
        base = json.loads(json.dumps(DEFAULT_CFG))
        def deep(d, b):
            for k, v in b.items():
                if isinstance(v, dict):
                    d.setdefault(k, {}); deep(d[k], v)
                else:
                    d.setdefault(k, v)
        deep(cfg, base)
    else:
        cfg = json.loads(json.dumps(DEFAULT_CFG))
        state_save("config.json", cfg)
    for k, v in os.environ.items():
        if k == "TELEGRAM_TOKEN": cfg["telegram_token"] = v
        if k == "TELEGRAM_CHAT_ID": cfg["telegram_chat_id"] = v
    return cfg

def state_load(path, default):
    try:
        with open(path, encoding="utf-8") as f: return json.load(f)
    except Exception:
        return default

def state_save(path, obj):
    try:
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            json.dump(obj, f, indent=2)
    except Exception as e:
        log("state_save %s failed: %s" % (path, e))

def http_get(url, timeout=30):
    req = urllib.request.Request(url, headers={"User-Agent": "puzzle-sniper/4.2"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")

def http_json(url, timeout=30):
    return json.loads(http_get(url, timeout))

def parse_keyspace(s, bits=0):
    if not s or not s.strip():
        return (1 << (bits - 1), (1 << bits) - 1) if bits else (1, N - 1)
    s = s.strip().lower()
    if ":" in s:
        a, b = s.split(":", 1)
        start = int(a, 16) if a else 1
        if b.startswith("+"):
            return start, start + int(b[1:], 16) - 1
        end = int(b, 16) if b else ((1 << bits) - 1 if bits else N - 1)
        if end <= start:
            if bits: start, end = 1 << (bits - 1), (1 << bits) - 1
            else: raise ValueError("keyspace end <= start")
        return start, end
    start = int(s, 16)
    return start, ((1 << bits) - 1 if bits else N - 1)

# =============================================================================
#  Telegram (long-poll, full menu)
# =============================================================================
TG_LOCK = threading.Lock()
RUNNING = [True]

def tg_call(method, params=None, timeout=35):
    params = params or {}
    tok = CFG.get("telegram_token")
    if not tok: return None
    url = "https://api.telegram.org/bot%s/%s" % (tok, method)
    data = urllib.parse.urlencode(params).encode()
    for _attempt in range(6):
        if not RUNNING[0]: return None
        try:
            req = urllib.request.Request(url, data=data)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code == 429:
                wait = int(e.headers.get("Retry-After", 5)) + 1
                log("telegram 429 - sleep %ds" % wait); time.sleep(min(wait, 60)); continue
            log("telegram HTTP %s" % e.code); return None
        except Exception:
            time.sleep(5)
    return None

def tg_send(text, chat=None):
    chat = chat or CFG.get("telegram_chat_id")
    if not CFG.get("telegram_token") or not chat: return
    if len(text) > 4000: text = text[:3990] + "\n...[truncated]"
    with TG_LOCK:
        tg_call("sendMessage", {"chat_id": chat, "text": text,
                                "parse_mode": "HTML",
                                "disable_web_page_preview": "true"})

def tg_send_menu(chat=None):
    chat = chat or CFG.get("telegram_chat_id")
    if not CFG.get("telegram_token") or not chat: return
    buttons = [
        [{"text": "🏠 Menu"}, {"text": "📊 Status"}, {"text": "📋 Queue"}],
        [{"text": "⚙️ Engine"}, {"text": "🔍 Solved"}, {"text": "💾 Wallet"}],
        [{"text": "🔓 Crack"}, {"text": "🏁 Ping"}, {"text": "🔃 Restart"}],
    ]
    markup = json.dumps({"keyboard": buttons, "resize_keyboard": True,
                         "one_time_keyboard": False})
    with TG_LOCK:
        tg_call("sendMessage", {"chat_id": chat,
                                "text": "<b>SNIPER 4.2 MENU</b> - tap a button:",
                                "parse_mode": "HTML", "reply_markup": markup})

def tg_close_menu(chat=None):
    chat = chat or CFG.get("telegram_chat_id")
    if not CFG.get("telegram_token") or not chat: return
    with TG_LOCK:
        tg_call("sendMessage", {"chat_id": chat, "text": "menu closed",
                                "reply_markup": json.dumps({"remove_keyboard": True})})

def tg_send_file(path, caption="", chat=None):
    chat = chat or CFG.get("telegram_chat_id")
    if not CFG.get("telegram_token") or not chat or not os.path.exists(path): return
    try:
        boundary = "----sniper" + str(int(time.time() * 1000))
        with open(path, "rb") as fh: body = fh.read()
        parts = [("--%s\r\nContent-Disposition: form-data; name=\"chat_id\"\r\n\r\n%s\r\n"
                  % (boundary, chat)).encode(),
                 ("--%s\r\nContent-Disposition: form-data; name=\"caption\"\r\n\r\n%s\r\n"
                  % (boundary, caption)).encode(),
                 ("--%s\r\nContent-Disposition: form-data; name=\"document\"; filename=\"%s\"\r\n"
                  "Content-Type: application/octet-stream\r\n\r\n"
                  % (boundary, os.path.basename(path))).encode(),
                 body, ("\r\n--%s--\r\n" % boundary).encode()]
        url = "https://api.telegram.org/bot%s/sendDocument" % CFG["telegram_token"]
        req = urllib.request.Request(
            url, data=b"".join(parts), method="POST",
            headers={"Content-Type": "multipart/form-data; boundary=%s" % boundary})
        with urllib.request.urlopen(req, timeout=60): pass
    except Exception as e:
        log("telegram sendDocument failed: %s" % e)

def tg_autodetect_chat():
    if CFG.get("telegram_chat_id") or not CFG.get("telegram_token"): return
    try:
        r = tg_call("getUpdates", {"timeout": 1, "allowed_updates": '["message"]'}, timeout=6)
        for u in (r or {}).get("result") or []:
            cid = (u.get("message") or {}).get("chat", {}).get("id")
            if cid:
                CFG["telegram_chat_id"] = cid
                state_save("config.json", CFG)
                log("telegram chat auto-detected: %s" % cid); return
    except Exception:
        pass

def tg_poll_loop():
    offset = 0
    while RUNNING[0]:
        try:
            r = tg_call("getUpdates", {"timeout": 50, "offset": offset,
                                       "allowed_updates": '["message"]'}, timeout=65)
            if not r:
                time.sleep(3); continue
            for u in r.get("result") or []:
                offset = u["update_id"] + 1
                msg = u.get("message") or {}
                txt = (msg.get("text") or "").strip()
                chat = msg.get("chat", {}).get("id")
                if txt and chat is not None: tg_handle_command(txt, chat)
        except Exception as e:
            log("telegram poll error: %s" % e); time.sleep(5)

def tg_handle_command(txt, chat):
    parts = txt.split(); cmd = parts[0].lower()
    def reply(s): tg_send(s, chat=chat)
    try:
        btn = {"🏠 Menu": "/menu", "📊 Status": "/status", "📋 Queue": "/queue",
               "⚙️ Engine": "/engine", "🔍 Solved": "/solved",
               "💾 Wallet": "/wallet", "🔓 Crack": "/crack",
               "🏁 Ping": "/ping", "🔃 Restart": "/restart"}
        if txt in btn:
            txt = btn[txt]; parts = txt.split(); cmd = parts[0].lower()
        if cmd == "/menu": tg_send_menu(chat=chat); return
        if cmd == "/close": tg_close_menu(chat=chat); return
        if cmd in ("/start", "/help"):
            if chat and not CFG.get("telegram_chat_id"):
                CFG["telegram_chat_id"] = chat; state_save("config.json", CFG)
            reply("<b>SNIPER 4.2</b> - full command list\n\n"
                  "<b>Menu:</b> /menu (tap buttons) /close\n"
                  "<b>Engine:</b> /status /queue /engine /solved /restart /resume\n"
                  "<b>Wallet:</b> /wallet PATH /diff A B /verifyblob /noise DIR\n"
                  "<b>Snipe:</b> /snipe URL (remote wallet.dat -> hash)\n"
                  "<b>Crack:</b> /crack /crackstatus /crackstop\n"
                  "<b>Puzzles:</b> /add N /remove ID /addaddr ADDR BITS /range N\n"
                  "<b>Keys:</b> /key ID /sweep ID /refresh /ping")
            tg_send_menu(chat=chat)
        elif cmd == "/status": reply("<b>STATUS</b>\n" + status_summary())
        elif cmd == "/queue": reply(snipe_queue_text())
        elif cmd == "/solved":
            evs = list(FOUND_HISTORY)[-15:][::-1] if FOUND_HISTORY else []
            reply("<b>SOLVE EVENTS</b>\n" + ("\n".join(evs) if evs else "none yet"))
        elif cmd == "/wallet":
            if len(parts) > 1: reply(wallet_scan_text(parts[1]))
            else: reply("usage: /wallet C:\\path\\wallet.dat")
        elif cmd == "/diff" and len(parts) > 2: reply(binary_diff(parts[1], parts[2]))
        elif cmd == "/noise" and len(parts) > 1: reply(noise_scan_text(parts[1]))
        elif cmd == "/verifyblob": reply(verify_blob_text())
        elif cmd == "/snipe" and len(parts) > 1:
            fn, _rep, hashes = snipe_dat(parts[1])
            reply("snipe: %d hash(es) extracted from %s" % (len(hashes), os.path.basename(fn)))
        elif cmd == "/crack":
            ok = start_crack()
            reply("crack started" if ok else "crack already running or hashcat missing")
        elif cmd == "/crackstatus":
            c = CRACK
            reply("crack: %s | step: %s | found: %s" %
                  ("RUN" if c["running"] else "IDLE", c["step"] or "-", c["found"] or "-"))
        elif cmd == "/crackstop": stop_crack(); reply("crack aborted")
        elif cmd == "/range" and len(parts) > 1:
            n = int(parts[1])
            reply("Puzzle #%d range 0x%x : 0x%x" % (n, 1 << (n - 1), (1 << n) - 1))
        elif cmd == "/add" and len(parts) > 1:
            ok = add_snipe(int(parts[1]))
            reply("queued #%s" % parts[1] if ok else "cannot queue #%s" % parts[1])
        elif cmd == "/remove" and len(parts) > 1:
            reply("removed" if remove_snipe(parts[1]) else "not in queue")
        elif cmd == "/addaddr" and len(parts) > 2:
            ok = add_addr_target(parts[1], int(parts[2]))
            reply("address target queued" if ok else "add failed")
        elif cmd == "/key" and len(parts) > 1: reply(key_report(parts[1]))
        elif cmd == "/sweep" and len(parts) > 1: reply(sweep_report(parts[1]))
        elif cmd == "/refresh": refresh_now(); reply("rescan done")
        elif cmd == "/ping": reply("PONG - uptime %s" % uptime_str())
        elif cmd == "/engine":
            a = ACTIVE
            reply("engine: %s | active: %s | target: %s | progress: %s" %
                  (a.get("engine"), "RUN" if a.get("proc") is not None else "IDLE",
                   a.get("num"), a.get("progress") or "-"))
        elif cmd == "/restart":
            kill_active(); reply("engine restarted (auto resume)")
        elif cmd == "/resume":
            n = force_resume(); reply("resumed %d targets" % n)
    except Exception as e:
        reply("error: %s" % e)

# =============================================================================
#  Scanners
# =============================================================================
def parse_puzzles(html):
    out = []
    for row in re.findall(r"<tr[^>]*>(.*?)</tr>", html, re.S):
        cells = [re.sub(r"<[^>]+>", "", c).strip()
                 for c in re.findall(r"<t[dh][^>]*>(.*?)</t[dh]>", row, re.S)]
        if len(cells) < 3: continue
        try: num = int(cells[0])
        except ValueError: continue
        if num < 1 or num > 160: continue
        rowtxt = " ".join(cells)
        addr = next((c for c in cells
                     if re.fullmatch(r"[13][1-9A-HJ-NP-Za-km-z]{25,34}", c)), "") or \
               next((c for c in cells if c.startswith("bc1")), "")
        pub = re.search(r"\b0[23][0-9a-fA-F]{64}\b", rowtxt)
        priv = re.search(r"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])", rowtxt)
        vals = re.findall(r"[0-9]+\.?[0-9]*", rowtxt)
        out.append({"num": num, "address": addr,
                    "pubkey": pub.group(0) if pub else "",
                    "priv": priv.group(0).lower() if priv else "",
                    "value": float(vals[-1]) if vals else 0.0,
                    "solved": bool(priv)})
    return {p["num"]: p for p in out}

def parse_puzzles_alt(html):
    out = {}
    blocks = re.split(r"Puzzle\s*(?:<[^>]+>)?\*{0,2}(\d{1,3})\*{0,2}\s*", html)
    for i in range(1, len(blocks), 2):
        num = int(blocks[i]); body = blocks[i + 1]
        if num < 1 or num > 160: continue
        m = re.search(r"([13][1-9A-HJ-NP-Za-km-z]{25,34}|bc1[a-zA-Z0-9]{38,59})", body)
        if not m: continue
        pub = re.search(r"Public key is known\.\s*(?:🔐)?\s*([0-9a-fA-F]{66})", body)
        priv = re.search(r"keys/btc/([0-9a-fA-F]{64})", body)
        val = re.search(r"🟢\s*([0-9]+\.?[0-9]*)\s*BTC", body)
        out[num] = {"num": num, "address": m.group(1),
                    "pubkey": pub.group(1).lower() if pub else "",
                    "priv": priv.group(1).lower() if priv else "",
                    "value": float(val.group(1)) if val else 0.0,
                    "solved": bool(priv)}
    return out

def lowest_unsolved(puzzles):
    for n in range(1, 161):
        p = puzzles.get(n)
        if p and not p["solved"]: return p
    return None

def scan_once():
    errs = []
    for src in CFG.get("sources", ["secretscan"]):
        try:
            url = PUZZLE_URL if src == "secretscan" else PUZZLE_URL2
            html = http_get(url)
            p = parse_puzzles(html) if src == "secretscan" else parse_puzzles_alt(html)
            if len(p) > 20: return p
            errs.append("%s: only %d rows" % (src, len(p)))
        except Exception as e:
            errs.append("%s: %s" % (src, e))
    raise RuntimeError("scan failed: " + "; ".join(errs))

# =============================================================================
#  Queue (persistent, self-healing on boot)
# =============================================================================
SNIPE_QUEUE = state_load("snipe_queue.json", [])
FOUND_HISTORY = deque(state_load("found_history.json", []), maxlen=200)
QUEUE_LOCK = threading.Lock()

def _norm_target(t, bits):
    lo, hi = parse_keyspace(t.get("keyspace", ""), bits)
    t["start"], t["end"] = lo, hi
    t["restart_count"] = t.get("restart_count", 0)
    t["paused_at"] = t.get("paused_at", 0)
    return t

def heal_state():
    """environment-reset healing: rebuild corrupted state, reset running->waiting."""
    global SNIPE_QUEUE
    if not isinstance(SNIPE_QUEUE, list): SNIPE_QUEUE = []
    with QUEUE_LOCK:
        clean = []
        for q in SNIPE_QUEUE:
            if not isinstance(q, dict) or not q.get("id"): continue
            q["status"] = "waiting"
            q.setdefault("restart_count", 0)
            q.setdefault("paused_at", 0)
            clean.append(q)
        SNIPE_QUEUE = clean
    state_save("snipe_queue.json", SNIPE_QUEUE)
    if not isinstance(FOUND_HISTORY, (list, tuple)): FOUND_HISTORY.clear()

def seed_targets():
    with QUEUE_LOCK:
        ids = {str(q["id"]) for q in SNIPE_QUEUE}
        for t in CFG.get("targets", []):
            tid = str(t["id"])
            if tid in ids: continue
            bits = int(t.get("bits") or 0)
            if bits < 1: continue
            if t.get("mode") == "kangaroo" and not on_curve(t.get("pubkey", "")):
                log("[queue] target %s pubkey not on curve - skipped" % tid); continue
            if t.get("mode") == "bitcrack" and not t.get("address"):
                log("[queue] target %s no address - skipped" % tid); continue
            q = _norm_target(dict(t), bits)
            q.update({"status": "waiting",
                      "ev": float(t.get("value") or 0) / ((1 << bits) - 1)})
            SNIPE_QUEUE.append(q); ids.add(tid)
            log("[queue] seeded target %s (%d-bit, %s mode)" % (tid, bits, t.get("mode")))
    if CFG["snipe"].get("auto_add_pubkey_puzzles"):
        try:
            puzzles = scan_once()
            for n in PUBKEY_PUZZLES:
                p = puzzles.get(n)
                if p and p["pubkey"] and not p["solved"]: add_snipe(n)
        except Exception as e:
            log("[queue] pubkey puzzle scan: %s" % e)
    state_save("snipe_queue.json", SNIPE_QUEUE)

def add_snipe(num):
    with QUEUE_LOCK:
        if any(str(q["id"]) == "p%d" % num for q in SNIPE_QUEUE): return False
        try: puzzles = scan_once()
        except Exception: return False
        p = puzzles.get(num)
        if not p or p["solved"]: return False
        bits = num
        if not CFG["snipe"]["min_bits"] <= bits <= CFG["snipe"]["max_bits"]: return False
        if p["pubkey"]:
            q = {"id": "p%d" % num, "mode": "kangaroo", "bits": bits, "num": num,
                 "pubkey": p["pubkey"], "address": p["address"],
                 "value": p["value"], "label": "Puzzle #%d" % num, "keyspace": ""}
        else:
            q = {"id": "p%d" % num, "mode": "bitcrack", "bits": bits, "num": num,
                 "address": p["address"], "value": p["value"],
                 "label": "Puzzle #%d (address mode)" % num, "keyspace": ""}
        _norm_target(q, bits)
        q.update({"status": "waiting", "ev": p["value"] / ((1 << bits) - 1)})
        SNIPE_QUEUE.append(q)
        SNIPE_QUEUE.sort(key=lambda z: -z["ev"])
        log("queued %s" % q["id"]); state_save("snipe_queue.json", SNIPE_QUEUE)
        return True

def add_addr_target(addr, bits):
    with QUEUE_LOCK:
        if any(str(q["id"]) == "a" + addr[:12] for q in SNIPE_QUEUE): return False
        if not 1 <= bits <= 160: return False
        q = {"id": "a" + addr[:12], "mode": "bitcrack", "bits": bits,
             "address": addr, "value": 0.0, "label": addr, "keyspace": ""}
        _norm_target(q, bits)
        q.update({"status": "waiting", "ev": 0.0})
        SNIPE_QUEUE.append(q); state_save("snipe_queue.json", SNIPE_QUEUE)
        log("queued address %s (%d-bit)" % (addr, bits))
        return True

def remove_snipe(tid):
    global SNIPE_QUEUE
    with QUEUE_LOCK:
        new = [q for q in SNIPE_QUEUE if str(q["id"]) != str(tid)]
        if len(new) == len(SNIPE_QUEUE): return False
        SNIPE_QUEUE = new; state_save("snipe_queue.json", SNIPE_QUEUE)
        return True

def force_resume():
    n = 0
    with QUEUE_LOCK:
        for q in SNIPE_QUEUE:
            if q.get("status") in ("paused", "waiting"):
                q["status"] = "waiting"; q["restart_count"] = 0; q["paused_at"] = 0; n += 1
        state_save("snipe_queue.json", SNIPE_QUEUE)
    return n

def snipe_queue_text():
    with QUEUE_LOCK:
        if not SNIPE_QUEUE: return "queue empty"
        return "\n".join(
            "%s %d-bit [%s] EV=%.1e restarts=%d  %s" %
            (q["id"], q.get("bits", 0), q.get("status"), q.get("ev", 0),
             q.get("restart_count", 0), q.get("label", "")[:40])
            for q in sorted(SNIPE_QUEUE, key=lambda z: -z.get("ev", 0)))

# =============================================================================
#  Engines + supervisor (no idle, crash/stall auto-restart)
# =============================================================================
ACTIVE = {"proc": None, "num": None, "engine": None, "workdir": None,
          "log": None, "progress": "", "started": 0, "last_log_mtime": 0}

def download_asset(repo, match_sub, exe_name):
    log("downloading %s from %s ..." % (exe_name, repo))
    rel = http_json("https://api.github.com/repos/%s/releases/latest" % repo)
    tag = rel.get("tag_name", "")
    direct = "https://github.com/%s/releases/download/%s/%s" % (repo, tag, exe_name)
    try:
        urllib.request.urlretrieve(direct, exe_name)
        if os.path.exists(exe_name) and os.path.getsize(exe_name) > 100000:
            log("%s ready (direct)" % exe_name); return os.path.abspath(exe_name)
    except Exception:
        pass
    for a in rel.get("assets", []):
        if a["name"].lower().endswith(".zip") and match_sub in a["name"].lower():
            urllib.request.urlretrieve(a["browser_download_url"], "dl.zip")
            with zipfile.ZipFile("dl.zip") as z: z.extractall("dl_tmp")
            os.remove("dl.zip")
            for root, _dirs, fs in os.walk("dl_tmp"):
                for f in fs:
                    if f.lower() == exe_name.lower():
                        shutil.move(os.path.join(root, f), exe_name); break
            shutil.rmtree("dl_tmp", ignore_errors=True)
            if os.path.exists(exe_name):
                log("%s ready (zip)" % exe_name); return os.path.abspath(exe_name)
    log("manual: download %s from https://github.com/%s/releases" % (exe_name, repo))
    return None

def ensure_kangaroo():
    name = "Kangaroo.exe" if IS_WIN else "kangaroo"
    if os.path.exists(name): return os.path.abspath(name)
    f = shutil.which(name)
    if f: return f
    if not CFG["engines"]["kangaroo"].get("auto_download"): return None
    return download_asset(KANGAROO_REPO, "kangaroo", name)

def ensure_bitcrack():
    name = "cuBitCrack.exe" if IS_WIN else "cuBitCrack"
    alt = "clBitCrack.exe" if IS_WIN else "clBitCrack"
    for cand in (name, alt):
        if os.path.exists(cand): return os.path.abspath(cand)
        f = shutil.which(cand)
        if f: return f
    if not CFG["engines"]["bitcrack"].get("auto_download"): return None
    return download_asset(BITCRACK_REPO, "cubitcrack", name)

def kangaroo_cmd(kexe, q):
    kc = CFG["engines"]["kangaroo"]
    args = [kexe]
    if kc.get("gpu"):
        args += ["-gpu", "-gpuId", str(kc.get("gpu_id", 0))]
    else:
        args += ["-t", str(kc.get("cpu_threads", 4))]
    args += ["-d", str(kc.get("dpbits", 26)), "-w", "save.work", "-wi", "600",
             "-o", "found.txt", "input.txt"]
    return args

def bitcrack_cmd(bexe, q):
    bc = CFG["engines"]["bitcrack"]
    args = [bexe, "--keyspace", "%x:%x" % (q["start"], q["end"]),
            "-o", "found.txt", "--continue", "save.txt"]
    if bc.get("compressed"): args.append("-c")
    if bc.get("uncompressed"): args.append("-u")
    args.append(q["address"])
    return args

def spawn(q, engine, exe):
    wd = os.path.join("work", str(q["id"]).replace("/", "_"))
    os.makedirs(wd, exist_ok=True)
    if engine == "kangaroo":
        write_text(os.path.join(wd, "input.txt"),
                   "%s %x %x\n" % (q["pubkey"], q["start"], q["end"]))
        cmd = kangaroo_cmd(exe, q)
    else:
        cmd = bitcrack_cmd(exe, q)
    log("[engine] start %s (%s) bits=%d: %s" %
        (q["id"], engine, q.get("bits", 0), " ".join(cmd)))
    lg = open(os.path.join(wd, "run.log"), "ab")
    kw = {}
    if IS_WIN:
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        if CFG.get("priority", "idle") == "idle": flags |= IDLE_PRIORITY
        else: flags |= BELOW_NORMAL_PRIORITY
        kw["creationflags"] = flags
    else:
        kw["preexec_fn"] = (lambda: os.nice(19)) if hasattr(os, "nice") else None
        if kw["preexec_fn"] is None: kw.pop("preexec_fn")
    try:
        pr = subprocess.Popen(cmd, cwd=wd, stdout=lg, stderr=subprocess.STDOUT, **kw)
    except Exception as e:
        log("[engine] spawn failed: %s" % e)
        with QUEUE_LOCK:
            for z in SNIPE_QUEUE:
                if str(z["id"]) == str(q["id"]): z["status"] = "waiting"; break
        lg.close(); time.sleep(30); return False
    ACTIVE.update(proc=pr, num=q["id"], engine=engine, workdir=wd, log=lg,
                  started=time.time(), progress="", last_log_mtime=time.time())
    return True

def parse_found(workdir):
    for fname in ("found.txt", "run.log"):
        f = os.path.join(workdir, fname)
        if not os.path.exists(f): continue
        txt = read_text(f)
        m = re.search(r"(?:priv|Priv|key|Key|private)\s*(?:key\s*)?\s*[=:]\s*(?:0x)?([0-9a-fA-F]{64})", txt)
        if m: return m.group(1).lower()
        m = re.search(r"\b([0-9a-fA-F]{64})\b", txt)
        if m: return m.group(1).lower()
    return None

def kill_active():
    a = ACTIVE
    if a["proc"] is not None:
        try: a["proc"].terminate()
        except Exception: pass
        time.sleep(1)
        if a["proc"].poll() is None:
            try: a["proc"].kill()
            except Exception: pass
    if a["log"] is not None:
        try: a["log"].close()
        except Exception: pass
    ACTIVE.update(proc=None, log=None, engine=None, workdir=None, progress="")

def engine_loop():
    kexe = bexe = None
    while RUNNING[0]:
        if kexe is None: kexe = ensure_kangaroo()
        if bexe is None: bexe = ensure_bitcrack()
        now = time.time()
        with QUEUE_LOCK:
            for z in SNIPE_QUEUE:
                if z.get("status") == "paused" and \
                        now - z.get("paused_at", 0) > CFG["supervisor"].get("auto_resume_after", 600):
                    z["status"] = "waiting"; z["restart_count"] = 0
                    log("[engine] auto-resumed %s" % z["id"])
        if ACTIVE["proc"] is not None:
            supervise_active(now); time.sleep(2); continue
        with QUEUE_LOCK:
            q = next((z for z in SNIPE_QUEUE if z.get("status") == "waiting"), None)
            if q: q["status"] = "running"
        if q is None:
            time.sleep(2); continue
        if q.get("mode") == "kangaroo" and kexe:
            if not spawn(q, "kangaroo", kexe):
                with QUEUE_LOCK:
                    for z in SNIPE_QUEUE:
                        if str(z["id"]) == str(q["id"]): z["status"] = "waiting"; break
            continue
        if q.get("mode") == "bitcrack" and bexe:
            if not spawn(q, "bitcrack", bexe):
                with QUEUE_LOCK:
                    for z in SNIPE_QUEUE:
                        if str(z["id"]) == str(q["id"]): z["status"] = "waiting"; break
            continue
        with QUEUE_LOCK:
            for z in SNIPE_QUEUE:
                if str(z["id"]) == str(q["id"]): z["status"] = "waiting"; break
        log("[engine] no engine binary for %s (kangaroo=%s bitcrack=%s)"
            % (q["id"], bool(kexe), bool(bexe)))
        time.sleep(30)

def supervise_active(now):
    a = ACTIVE
    qn = a["num"]; wd = a["workdir"]
    found = parse_found(wd)
    if found:
        log("[engine] KEY FOUND for %s: %s" % (qn, found))
        kill_active(); handle_found(qn, found); return
    rc = a["proc"].poll()
    if rc is not None:
        kill_active()
        with QUEUE_LOCK:
            q = next((z for z in SNIPE_QUEUE if str(z["id"]) == str(qn)), None)
        if q and parse_found(wd):
            handle_found(qn, parse_found(wd)); return
        if q:
            if q.get("restart_count", 0) < CFG["supervisor"].get("max_restarts", 5):
                q["status"] = "waiting"; q["restart_count"] = q.get("restart_count", 0) + 1
                log("[engine] %s exited rc=%d - restart %d (resume workfile)"
                    % (qn, rc, q["restart_count"]))
                deadline = now + CFG["supervisor"].get("restart_cooldown", 30)
                while time.time() < deadline and RUNNING[0]: time.sleep(2)
            else:
                q["status"] = "paused"; q["paused_at"] = time.time()
                log("[engine] %s paused (max restarts)" % qn)
                tg_send("<b>ENGINE PAUSED</b> %s after %d restarts - send /resume"
                        % (qn, q["restart_count"]))
        state_save("snipe_queue.json", SNIPE_QUEUE)
        return
    try:
        lf = os.path.join(wd, "run.log")
        mtime = os.path.getmtime(lf) if os.path.exists(lf) else 0
        if mtime and os.path.getsize(lf) > 0:
            with open(lf, "rb") as f:
                f.seek(max(0, os.path.getsize(lf) - 8000))
                tail = f.read().decode("utf-8", "replace")
            lines = [l for l in tail.splitlines() if l.strip()]
            if lines: a["progress"] = re.sub(r"\s+", " ", lines[-1].strip())[:160]
        if mtime > a["last_log_mtime"]: a["last_log_mtime"] = mtime
        elif now - a["started"] > CFG["supervisor"].get("stall_seconds", 180):
            log("[engine] %s stalled (no log activity) - restarting" % qn)
            kill_active()
            with QUEUE_LOCK:
                for z in SNIPE_QUEUE:
                    if str(z["id"]) == str(qn):
                        z["status"] = "waiting"
                        z["restart_count"] = z.get("restart_count", 0) + 1
                        break
            state_save("snipe_queue.json", SNIPE_QUEUE)
    except Exception:
        pass

def handle_found(num, privhex):
    with QUEUE_LOCK:
        q = next((z for z in SNIPE_QUEUE if str(z["id"]) == str(num)), None)
    address = q["address"] if q else ""
    wif = hex_to_wif(privhex)
    match = verify_key(privhex, address) if address else None
    tag = str(num).replace("/", "_")
    fn_hex = "FOUND_%s_HEX.txt" % tag; fn_wif = "FOUND_%s_WIF.txt" % tag
    write_text(fn_hex, privhex); write_text(fn_wif, wif)
    ev = "KEY %s %s addr=%s verify=%s" % (num, privhex, address, match or "FAIL")
    log(ev); FOUND_HISTORY.append(ev)
    state_save("found_history.json", list(FOUND_HISTORY))
    tg_send("<b>KEY FOUND - %s</b>\nHEX: <code>%s</code>\nWIF: <code>%s</code>\n"
            "addr: %s\nverify: %s\n<pre>%s</pre>\npayout: %s\nfiles: %s, %s"
            % (num, privhex, wif, address, match or "FAIL", wif_trace(wif),
               CFG["payout_address"] or "(not set)", fn_hex, fn_wif))
    for fp in (fn_hex, fn_wif): tg_send_file(fp, caption="%s key" % num)
    if CFG.get("auto_sweep") and CFG.get("payout_address") and match == "P2PKH":
        try:
            h, total, fee, nin = build_sweep(privhex, address, CFG["payout_address"])
            write_text("SWEEP_%s.hex" % tag, h)
            tg_send("sweep built: %d inputs -> %s (SWEEP_%s.hex)" %
                    (nin, CFG["payout_address"], tag))
            if CFG.get("broadcast_on_solve"):
                txid = broadcast_raw(h)
                tg_send("BROADCAST %s" % txid)
        except Exception as e:
            tg_send("sweep failed: %s" % e)
    elif CFG.get("auto_sweep"):
        tg_send("auto_sweep skipped: %s" % (match or addr_note(address)))
    with QUEUE_LOCK:
        SNIPE_QUEUE[:] = [z for z in SNIPE_QUEUE if str(z["id"]) != str(num)]
    state_save("snipe_queue.json", SNIPE_QUEUE)

# =============================================================================
#  Sweep (P2PKH only)
# =============================================================================
def varint(n):
    if n < 0xFD: return bytes([n])
    if n <= 0xFFFF: return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF: return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")

def push(b):
    if len(b) < 0x4C: return bytes([len(b)]) + b
    return b"\x4c" + len(b).to_bytes(1, "little") + b

def script_from_address(addr):
    if addr.startswith(("1", "3")):
        raw = b58check_decode(addr)
        if len(raw) != 21: raise ValueError("bad address")
        if raw[0] == 0x00: return bytes.fromhex("76a914") + raw[1:] + bytes.fromhex("88ac")
        if raw[0] == 0x05: return bytes.fromhex("a914") + raw[1:] + b"\x87"
        raise ValueError("unsupported version")
    if addr.startswith("bc1"):
        dec = bech32_decode(addr)
        if not dec or dec[0] != "bc": raise ValueError("bad bech32")
        prog = convertbits(dec[1], 5, 8, False)
        if prog is None: raise ValueError("bad witness program")
        if dec[1][0] == 0: return bytes([0x00, len(prog)]) + prog
        return bytes([0x50 + dec[1][0], len(prog)]) + prog
    raise ValueError("unsupported address %s" % addr)

def build_sweep(privhex, target_addr, payout, api="https://mempool.space/api"):
    priv = bytes.fromhex(privhex.zfill(64))
    if verify_key(privhex, target_addr) != "P2PKH":
        raise ValueError("sweep: only legacy P2PKH (%s)" % addr_note(target_addr))
    pub = pubkey_compressed(priv)
    raw = b58check_decode(target_addr)
    sc = bytes.fromhex("76a914") + raw[1:] + bytes.fromhex("88ac")
    utxos = [u for u in http_json("%s/address/%s/utxo" % (api, target_addr))
             if u.get("status", {}).get("confirmed")]
    if not utxos: raise RuntimeError("no confirmed UTXOs")
    total = sum(u["value"] for u in utxos)
    fee = max(1000, ((2 * (10 + 147 * len(utxos) + 31) + 999) // 1000) * 1000)
    if total <= fee: raise RuntimeError("balance %d < fee %d" % (total, fee))
    out = script_from_address(payout); outval = total - fee
    ins = [(bytes.fromhex(u["txid"])[::-1], u["vout"]) for u in utxos]
    sigs = []
    for txid, vout in ins:
        pre = (1).to_bytes(4, "little")
        for t2, v2 in ins:
            pre += t2 + v2.to_bytes(4, "little") + varint(len(sc)) + sc + b"\xff\xff\xff\xfd"
        pre += varint(1) + outval.to_bytes(8, "little") + varint(len(out)) + out
        pre += b"\x00\x00\x00\x00" + b"\x01\x00\x00\x00"
        sigs.append(_sign(priv, int.from_bytes(sha256d(pre), "big")) + b"\x01")
    tx = (1).to_bytes(4, "little") + varint(len(ins))
    for (txid, vout), sig in zip(ins, sigs):
        ss = push(sig) + push(pub)
        tx += txid + vout.to_bytes(4, "little") + varint(len(ss)) + ss + b"\xff\xff\xff\xfd"
    tx += varint(1) + outval.to_bytes(8, "little") + varint(len(out)) + out + b"\x00\x00\x00\x00"
    return tx.hex(), total, fee, len(ins)

def broadcast_raw(rawhex, api="https://mempool.space/api"):
    req = urllib.request.Request(api + "/tx", data=rawhex.encode(),
                                 headers={"Content-Type": "text/plain"}, method="POST")
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read().decode().strip()

# =============================================================================
#  Monitor thread
# =============================================================================
def monitor_loop():
    while RUNNING[0]:
        try: puzzles = scan_once()
        except Exception as e:
            log("scan failed: %s" % e); time.sleep(CFG["poll_interval"]); continue
        old = state_load("monitor_state.json", {})
        for n in sorted(puzzles):
            p, o = puzzles[n], old.get(str(n), {})
            if not o: continue
            if o.get("priv") != p["priv"] and p["priv"]:
                ev = "SOLVED #%d key=%s" % (n, p["priv"])
                log(ev); FOUND_HISTORY.append(ev)
                tg_send("<b>PUZZLE #%d SOLVED</b>\nkey: <code>%s</code>\nWIF: <code>%s</code>"
                        % (n, p["priv"], hex_to_wif(p["priv"])))
            elif o.get("pubkey") != p["pubkey"] and p["pubkey"]:
                ev = "PUBKEY EXPOSED #%d %s (%.3f BTC)" % (n, p["pubkey"], p["value"])
                log(ev); FOUND_HISTORY.append(ev)
                tg_send("<b>PUBLIC KEY EXPOSED</b> puzzle #%d\n<code>%s</code>\n%.3f BTC - queued"
                        % (n, p["pubkey"], p["value"]))
                add_snipe(n)
            elif abs(o.get("value", 0) - p["value"]) > 0.01:
                log("value update #%d: %.3f BTC" % (n, p["value"]))
                tg_send("puzzle #%d value now %.3f BTC" % (n, p["value"]))
        lo_new = lowest_unsolved(puzzles); lo_old = lowest_unsolved(old)
        if lo_new and (not lo_old or lo_old["num"] != lo_new["num"]):
            tg_send("<b>LOWEST UNSOLVED</b> now #%d (%.3f BTC)" % (lo_new["num"], lo_new["value"]))
        state_save("monitor_state.json", {str(k): v for k, v in puzzles.items()})
        state_save("found_history.json", list(FOUND_HISTORY))
        time.sleep(CFG["poll_interval"])

def refresh_now():
    try:
        p = scan_once(); lo = lowest_unsolved(p)
        log("refresh: %d puzzles, lowest unsolved #%s (%.3f BTC)" %
            (len(p), lo["num"] if lo else "?", lo["value"] if lo else 0))
    except Exception as e:
        log("refresh error: %s" % e)

# =============================================================================
#  WALLET RECOVERY MODULE
# =============================================================================
def ascii_safe(b, n=32):
    return "".join(chr(c) if 32 <= c < 127 else "." for c in b[:n])

def binary_diff(path_a, path_b, block=4096):
    if not os.path.exists(path_a) or not os.path.exists(path_b):
        return "missing file"
    size_a, size_b = os.path.getsize(path_a), os.path.getsize(path_b)
    out = ["diff %s (%d B) vs %s (%d B)" % (os.path.basename(path_a), size_a,
                                            os.path.basename(path_b), size_b)]
    if size_a != size_b: out.append("sizes differ by %d bytes" % abs(size_a - size_b))
    regions = []
    with open(path_a, "rb") as fa, open(path_b, "rb") as fb:
        off = 0
        while True:
            a = fa.read(block); b = fb.read(block)
            if not a and not b: break
            n = min(len(a), len(b))
            if n and a[:n] != b[:n]:
                d0 = next(i for i in range(n) if a[i] != b[i])
                d1 = n - 1
                while d1 > d0 and a[d1] == b[d1]: d1 -= 1
                regions.append((off + d0, off + d1))
            off += block
    merged = []
    for s, e in regions:
        if merged and s <= merged[-1][1] + 64:
            merged[-1] = (merged[-1][0], max(merged[-1][1], e))
        else:
            merged.append((s, e))
    if not merged:
        out.append("IDENTICAL files"); return "\n".join(out)
    out.append("%d differing region(s):" % len(merged))
    for s, e in merged[:40]:
        out.append("  0x%08x .. 0x%08x  (%d bytes)" % (s, e, e - s + 1))
    if len(merged) > 40: out.append("  ... %d more regions" % (len(merged) - 40))
    s, e = merged[0]
    with open(path_a, "rb") as fa, open(path_b, "rb") as fb:
        fa.seek(s); fb.seek(s); la = fa.read(32); lb = fb.read(32)
    out.append("first diff @ 0x%08x" % s)
    out.append("  A: %s | %s" % (la.hex(" "), ascii_safe(la)))
    out.append("  B: %s | %s" % (lb.hex(" "), ascii_safe(lb)))
    return "\n".join(out)

def noise_scan_text(root):
    """Hunt backup wallet copies near a path: *.bak, walletbackups\\, *.dat~"""
    hits = []
    if os.path.isfile(root): root = os.path.dirname(os.path.abspath(root))
    for base, dirs, files in os.walk(root):
        for f in files:
            fl = f.lower()
            if fl in ("wallet.dat", "wallet.dat.bak", "wallet.dat.old") or \
               fl.startswith("wallet.dat") or (fl.endswith(".dat") and "wallet" in fl):
                p = os.path.join(base, f)
                try: sz = os.path.getsize(p)
                except Exception: sz = 0
                hits.append("%8d  %s" % (sz, p))
    return ("noise scan %s\n" % root) + ("\n".join(hits[:80]) if hits else "nothing found")

def find_all(hay, needle):
    out = []; i = 0
    while True:
        i = hay.find(needle, i)
        if i < 0: break
        out.append(i); i += 1
    return out

def _varint(buf, off):
    if off >= len(buf): return None, off
    b0 = buf[off]
    if b0 < 0xfd: return b0, off + 1
    if b0 == 0xfd and off + 3 <= len(buf): return struct.unpack("<H", buf[off+1:off+3])[0], off + 3
    if b0 == 0xfe and off + 5 <= len(buf): return struct.unpack("<I", buf[off+1:off+5])[0], off + 5
    return None, off

def _try_mkey(buf, off):
    for pad in range(0, 6):
        o = off + 4 + pad
        if o + 16 > len(buf): continue
        salt = buf[o:o+8]; method = struct.unpack("<I", buf[o+8:o+12])[0]
        iters = struct.unpack("<I", buf[o+12:o+16])[0]
        if method != 0 or not (1 <= iters <= 10000000): continue
        if salt == b"\x00" * 8: continue
        for skip in (0, 1):
            c = o + 16 + skip
            ln, c2 = _varint(buf, c)
            if ln is None: continue
            ck = buf[c2:c2+ln]
            if len(ck) == ln and 32 <= ln <= 64:
                return {"salt": salt.hex(), "iters": iters, "ckey": ck.hex()}
    return None

def _try_ckey(buf, off):
    for pad in range(0, 5):
        o = off + 5 + pad
        if o + 33 > len(buf): continue
        pub = buf[o:o+33]
        if not on_curve_bytes(pub): continue
        for mode in (0, 1):
            c = o + 33
            if mode == 1:
                ln, c2 = _varint(buf, c)
                if ln is None: continue
            else:
                ln, c2 = 48, c
            if c2 + ln <= len(buf):
                return {"pub": pub, "enc": buf[c2:c2+ln].hex()}
    return None

def wallet_scan_text(fname):
    if not os.path.exists(fname): return "file not found: %s" % fname
    data = open(fname, "rb").read()
    out = ["wallet: %s (%d bytes)" % (fname, len(data))]
    mkeys, ckeys = [], []
    for off in find_all(data, b"mkey"):
        m = _try_mkey(data, off)
        if m:
            mkeys.append((off, m))
            out.append("[+] mkey @ 0x%x salt=%s iters=%d" % (off, m["salt"], m["iters"]))
            out.append("    hashcat11300: $bitcoin$64$%s$16$%s$%d$2$00$2$00"
                       % (m["ckey"], m["salt"], m["iters"]))
    for off in find_all(data, b"ckey"):
        c = _try_ckey(data, off)
        if c:
            ckeys.append((off, c))
            out.append("[+] ckey @ 0x%x pub=%s" % (off, c["pub"].hex()))
            out.append("    address: %s" % b58check_encode(b"\x00" + hash160(c["pub"])))
    for off in find_all(data, b"key"):
        if any(abs(off - x) < 10 for x in
               find_all(data, b"mkey") + find_all(data, b"ckey") + find_all(data, b"pkey")):
            continue
        for pad in range(0, 5):
            o = off + 3 + pad
            if o + 65 > len(data): continue
            pub = data[o:o+33]
            if not on_curve_bytes(pub): continue
            priv = data[o+33:o+65]
            try: got = compress(_mul(int.from_bytes(priv, "big")))
            except Exception: continue
            if got == pub:
                out.append("[!!!] PLAINTEXT KEY @ 0x%x" % off)
                out.append("    address : %s" % b58check_encode(b"\x00" + hash160(pub)))
                out.append("    priv hex : %s" % priv.hex())
                out.append("    WIF      : %s" % b58check_encode(b"\x80" + priv + b"\x01"))
    for off in find_all(data, b"pkey"):
        for pad in range(0, 5):
            o = off + 4 + pad
            if o + 33 <= len(data):
                pub = data[o:o+33]
                if on_curve_bytes(pub):
                    out.append("[+] pkey @ 0x%x address %s" %
                               (off, b58check_encode(b"\x00" + hash160(pub))))
    if mkeys and ckeys:
        _off, m = mkeys[0]; _o2, c = ckeys[0]
        x = int.from_bytes(c["pub"][1:], "big")
        y2 = (pow(x, 3, P) + 7) % P
        y = pow(y2, (P + 1) // 4, P)
        if (y * y) % P == y2:
            uncomp = b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")
            dec = str(int.from_bytes(uncomp, "big"))
            out.append("[+] hashcat11300 (96-byte verified, FP-proof): "
                       "$bitcoin$96$%s$16$%s$%d$96$%s"
                       % (c["enc"], m["salt"], m["iters"], dec))
    if not mkeys and not ckeys:
        out.append("no mkey/ckey records found (unencrypted or different format?)")
    return "\n".join(out)

def snipe_dat(url):
    """Download a remote wallet.dat, scan it, extract hashcat 11300 hashes."""
    name = os.path.basename(url.split("?")[0]) or "remote_wallet.dat"
    fn = os.path.join(tempfile.gettempdir(), "snipe_" + name)
    log("[snipe] downloading %s" % url)
    req = urllib.request.Request(url, headers={"User-Agent": "puzzle-sniper/4.2"})
    with urllib.request.urlopen(req, timeout=120) as r, open(fn, "wb") as f:
        shutil.copyfileobj(r, f)
    log("[snipe] saved %s (%d bytes)" % (fn, os.path.getsize(fn)))
    report = wallet_scan_text(fn)
    print(report)
    hashes = re.findall(r"\$bitcoin\$\d+\$[0-9a-fA-F]+(?:\$[^ \n]+)+", report)
    if hashes:
        write_text("wallet.hash", "\n".join(hashes) + "\n")
        log("[snipe] %d hash(es) -> wallet.hash ; run: --crack" % len(hashes))
        tg_send("<b>SNIPE DAT</b>\n%s\n%s" % (url, report[:1500]))
    else:
        log("[snipe] no hashcat hash extracted")
    return fn, report, hashes

def parse_bitcoin_hash(line):
    parts = line.strip().split("$")
    if len(parts) < 7 or parts[1] != "bitcoin":
        raise ValueError("not a $bitcoin$ hash")
    mk_len = int(parts[2]); mk = parts[3]
    salt_len = int(parts[4]); salt = parts[5]
    iters = int(parts[6])
    if len(mk) != mk_len or len(salt) != salt_len:
        raise ValueError("length mismatch")
    return {"mkey": mk, "salt": salt, "iters": iters}

def decode_blob(s):
    return "".join(chr(int(x)) for x in s.split())

def verify_blob_text(blob=None, target=None):
    blob = blob or BLOB_STR
    target = target or CFG["wallet"].get("target_address") or WALLET_TARGET
    dec = decode_blob(blob)
    out = ["decoded decimal string (%d digits): %s" % (len(dec), dec)]
    d = int(dec)
    if not 0 < d < N:
        out.append("NOT in secp256k1 range - not a private key (try as password)")
        return "\n".join(out)
    want = b58check_decode(target)
    for name in ("compressed", "uncompressed"):
        pt = _mul(d); x, y = pt
        if name == "compressed": pub = compress(pt)
        else: pub = b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")
        h = hash160(pub)
        addr = b58check_encode(b"\x00" + h)
        out.append("%-13s %s  %s" % (name, addr, "*** MATCH ***" if h == want else "no match"))
    out.append("hex key: %064x" % d)
    return "\n".join(out)

# ---- hashcat orchestration --------------------------------------------------
CRACK = {"proc": None, "running": False, "found": "", "step": "", "started": 0}
CRACK_LOCK = threading.Lock()

def hashcat_bin():
    for c in (("hashcat.exe", "hashcat") if IS_WIN else ("hashcat",)):
        if shutil.which(c): return c
        if os.path.exists(c): return os.path.abspath(c)
    return None

def check_crack_found(potfile, hashfile):
    hb = hashcat_bin()
    try:
        r = subprocess.run([hb, "-m", "11300", "--potfile-path", potfile,
                            hashfile, "--show"], capture_output=True, text=True, timeout=30)
        for line in r.stdout.splitlines():
            if line.startswith("$bitcoin$") and ":" in line:
                return line.split(":", 1)[1]
    except Exception:
        pass
    return ""

def crack_commands(hashfile, potfile, outfile, prefix, max_digits):
    hb = hashcat_bin()
    base = [hb, "-m", "11300", "--potfile-path", potfile, "-O", "-w", "3",
            "--outfile", outfile]
    mask = prefix + "?d" * max_digits
    return [
        ("mask %s + digits (4..%d)" % (prefix, max_digits),
         base + ["-a", "3", "-i", "--increment-min", "4",
                 "--increment-max", str(max_digits), hashfile, mask]),
        ("hybrid prefixes + 8 digits",
         base + ["-a", "6", hashfile, "prefixes.txt", "?d?d?d?d?d?d?d?d"]),
        ("pure digits brute (8..12)",
         base + ["-a", "3", "-i", "--increment-min", "8", "--increment-max", "12",
                 hashfile, "?d?d?d?d?d?d?d?d?d?d?d?d"]),
        ("straight candidates (decoded blob etc.)",
         base + ["-a", "0", hashfile, "cand.txt"]),
        ("ru layout mutants + suffixes", base + ["-a", "0", hashfile, "ru_layout.txt"]),
    ]

def prepare_crack_files():
    write_text("prefixes.txt", "\n".join(
        ["Mandriana", "Mandriana_", "mandriana", "mandriana_", "MANDRIANA",
         "M4ndriana", "Mandriana!", "Mandriana.", "Mandriana1", "Mandriana123",
         "mandriana!", ""]) + "\n")
    dec = decode_blob(BLOB_STR)
    write_text("cand.txt", "\n".join(
        [dec, "Mandriana_" + dec, "Mandriana" + dec, "mandriana_" + dec,
         dec + "Mandriana_"]) + "\n")
    if not os.path.exists("ru_layout.txt"):
        write_text("ru_layout.txt", "\n".join(
            ["15npoeYGso1qyFAo7Wzw35s4fXMDh5ryrj", "15npoeYGso1qyFAo7Wzw35s4fXMDh5ryrj.dat",
             "wallet", "bitcoin", "parol", "пароль"]) + "\n")

def crack_worker(hashfile):
    hb = hashcat_bin()
    if not hb:
        log("[crack] hashcat not found in PATH"); return
    potfile, outfile = "sniper.pot", "crack_found.txt"
    prepare_crack_files()
    prefix = CFG["wallet"].get("prefix") or "Mandriana_"
    maxd = int(CFG["wallet"].get("max_digits") or 10)
    CRACK["running"] = True; CRACK["found"] = ""; CRACK["started"] = time.time()
    try:
        for label, cmd in crack_commands(hashfile, potfile, outfile, prefix, maxd):
            if not CRACK["running"]: break
            CRACK["step"] = label
            log("[crack] step: %s" % label)
            tg_send("[crack] started: %s" % label)
            try:
                pr = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL)
                CRACK["proc"] = pr
                while pr.poll() is None and CRACK["running"]: time.sleep(5)
                if not CRACK["running"]:
                    try: pr.terminate()
                    except Exception: pass
                    break
            except Exception as e:
                log("[crack] launch failed: %s" % e); continue
            pw = check_crack_found(potfile, hashfile)
            if pw:
                CRACK["found"] = pw
                log("[crack] FOUND: %s" % pw)
                write_text("FOUND_PASSWORD.txt", pw + "\n")
                tg_send("<b>WALLET PASSWORD FOUND</b>\n<code>%s</code>\nfile: FOUND_PASSWORD.txt" % pw)
                return
    finally:
        CRACK["running"] = False; CRACK["proc"] = None
        log("[crack] finished (found=%s)" % (CRACK["found"] or "no"))

def start_crack():
    if not os.path.exists("wallet.hash"):
        write_text("wallet.hash", WALLET_HASH + "\n")
    if not hashcat_bin():
        log("[crack] hashcat not found - install hashcat and put it in PATH")
        return False
    with CRACK_LOCK:
        if CRACK["running"]: return False
        threading.Thread(target=crack_worker, args=("wallet.hash",), daemon=True).start()
    return True

def stop_crack():
    CRACK["running"] = False
    if CRACK["proc"] is not None:
        try: CRACK["proc"].terminate()
        except Exception: pass

# =============================================================================
#  RU <-> EN keyboard-layout wordlist generator (ЙЦУКЕН / QWERTY)
# =============================================================================
_LAYOUT = [
    ("q","й","Q","Й"),("w","ц","W","Ц"),("e","у","E","У"),("r","к","R","К"),
    ("t","е","T","Е"),("y","н","Y","Н"),("u","г","U","Г"),("i","ш","I","Ш"),
    ("o","щ","O","Щ"),("p","з","P","З"),("[","х","{","Х"),("]","ъ","}","Ъ"),
    ("a","ф","A","Ф"),("s","ы","S","Ы"),("d","в","D","В"),("f","а","F","А"),
    ("g","п","G","П"),("h","р","H","Р"),("j","о","J","О"),("k","л","K","Л"),
    ("l","д","L","Д"),(";","ж",":","Ж"),("'","э",'"',"Э"),
    ("z","я","Z","Я"),("x","ч","X","Ч"),("c","с","C","С"),("v","м","V","М"),
    ("b","и","B","И"),("n","т","N","Т"),("m","ь","M","Ь"),
    (",","б","<","Б"),(".","ю",">","Ю"),("/",".","?",","),
]
RU2EN = {}; EN2RU = {}
for _en_l, _ru_l, _en_u, _ru_u in _LAYOUT:
    RU2EN[_ru_l] = _en_l; RU2EN[_ru_u] = _en_u
    EN2RU[_en_l] = _ru_l; EN2RU[_en_u] = _ru_u

def layout_mutants(s):
    out = set()
    out.add("".join(RU2EN.get(c, c) for c in s))
    out.add("".join(EN2RU.get(c, c) for c in s))
    out.add(s.swapcase()); out.add(s.lower()); out.add(s.upper())
    return [x for x in out if x and x != s]

def write_layout_wordlist(src, dst, append_suffixes=True):
    n = 0
    suffixes = ("1970","1971","1980","1990","1991","01","1","123","!") if append_suffixes else ()
    with open(src, encoding="utf-8", errors="replace") as fi, \
         open(dst, "w", encoding="utf-8", newline="\n") as fo:
        for line in fi:
            w = line.rstrip("\r\n")
            if not w or len(w) > 64: continue
            cands = {w} | set(layout_mutants(w))
            for c in cands:
                fo.write(c + "\n"); n += 1
                for suf in suffixes:
                    fo.write(c + suf + "\n"); n += 1
    log("[wordlist] wrote %d candidates -> %s" % (n, dst))
    return n

# =============================================================================
#  Status / reports / analyze
# =============================================================================
START_TIME = time.time()

def uptime_str():
    s = int(time.time() - START_TIME)
    return "%dh%02dm%02ds" % (s // 3600, s % 3600 // 60, s % 60)

def status_summary():
    lines = ["uptime: %s" % uptime_str()]
    try:
        p = scan_once(); lo = lowest_unsolved(p)
        lines.append("lowest unsolved: #%d (%.3f BTC)" % (lo["num"], lo["value"])
                     if lo else "all solved?")
    except Exception as e:
        lines.append("scan error: %s" % e)
    a = ACTIVE
    lines.append("engine: %s | active: %s | target: %s" %
                 (a["engine"] or "-", "RUN" if a["proc"] is not None else "IDLE",
                  a["num"] or "-"))
    if a["proc"] is not None: lines.append("progress: %s" % a["progress"])
    c = CRACK
    lines.append("crack: %s | step: %s | found: %s" %
                 ("RUN" if c["running"] else "IDLE", c["step"] or "-", c["found"] or "-"))
    lines.append("queue:\n" + snipe_queue_text())
    return "\n".join(lines)

def key_report(tid):
    tag = str(tid).replace("/", "_")
    for f in ("FOUND_%s_HEX.txt" % tag, "FOUND_%s_WIF.txt" % tag):
        if os.path.exists(f): return "%s:\n%s" % (f, read_text(f).strip())
    return "no key found for %s yet" % tid

def sweep_report(tid):
    tag = str(tid).replace("/", "_")
    hx = "FOUND_%s_HEX.txt" % tag
    if not os.path.exists(hx): return "no key for %s" % tid
    priv = read_text(hx).strip()
    with QUEUE_LOCK:
        q = next((z for z in SNIPE_QUEUE if str(z["id"]) == str(tid)), None)
    addr = q["address"] if q else ""
    if not CFG.get("payout_address"): return "set payout_address in config.json first"
    try:
        h, total, fee, nin = build_sweep(priv, addr, CFG["payout_address"])
        write_text("SWEEP_%s.hex" % tag, h)
        return ("sweep built - %d inputs, %d sat -> %s (fee %d)\nfile: SWEEP_%s.hex"
                % (nin, total - fee, CFG["payout_address"], fee, tag))
    except Exception as e:
        return "sweep failed: %s" % e

def analyze_pub(pub):
    pub = pub.strip().lower()
    if not on_curve(pub):
        return "invalid or off-curve pubkey (need 02/03 + 64 hex)"
    for n, kp in KNOWN_PUZZLE_PUB.items():
        if pub == kp:
            lo, hi = 1 << (n - 1), (1 << n) - 1
            return ("MATCH puzzle #%d - kangaroo range 0x%x..0x%x (bits=%d)\n"
                    "expected work ~2.37*sqrt(2^%d) ops; at 3 Gops/s ~%.1e seconds"
                    % (n, lo, hi, n, n - 1, 2.37 * 2 ** ((n + 1) / 2) / 3e9))
    return ("no known puzzle match -> private key uniform in 2^256\n"
            "no valid bit-range inference exists; kangaroo needs a bounded range.\n"
            "expected work ~2^128 ops ~ 1e22 years at 3 Gops/s - not practically solvable.")

# =============================================================================
#  Demo / selftest / startup / main
# =============================================================================
def gen_demo_target(bits=32):
    import secrets
    lo, hi = 1 << (bits - 1), (1 << bits) - 1
    k = secrets.randbelow(hi - lo + 1) + lo
    pub = pubkey_compressed(k.to_bytes(32, "big"))
    return k, pub.hex(), derive_addresses(pub)[0], lo, hi

def demo_run(bitcrack=False):
    k = None
    if not bitcrack:
        k, pub, addr, lo, hi = gen_demo_target(32)
        q = {"id": "demo", "mode": "kangaroo", "bits": 32, "pubkey": pub,
             "address": addr, "value": 0.0, "label": "demo", "keyspace": "",
             "start": lo, "end": hi, "status": "waiting", "ev": 0.0,
             "restart_count": 0, "paused_at": 0}
        CFG["engines"]["kangaroo"]["dpbits"] = 18
    else:
        q = {"id": "demo10", "mode": "bitcrack", "bits": 10,
             "address": "1LeBZP5QCwwgXRtmVUvTVrraqPUokyLHqe", "value": 0.0,
             "label": "demo10", "keyspace": "", "start": 0x200, "end": 0x3ff,
             "status": "waiting", "ev": 0.0, "restart_count": 0, "paused_at": 0}
    with QUEUE_LOCK:
        SNIPE_QUEUE[:] = [z for z in SNIPE_QUEUE if z["id"] not in ("demo", "demo10")]
        SNIPE_QUEUE.append(q)
    threading.Thread(target=engine_loop, daemon=True).start()
    log("[demo] running %s demo - waiting for key ..." %
        ("bitcrack" if bitcrack else "kangaroo"))
    deadline = time.time() + 900
    while time.time() < deadline and RUNNING[0]:
        with QUEUE_LOCK:
            gone = not any(z["id"] == q["id"] for z in SNIPE_QUEUE)
        if gone:
            if os.path.exists("FOUND_%s_HEX.txt" % q["id"]):
                got = read_text("FOUND_%s_HEX.txt" % q["id"]).strip()
                want = "%x" % k if k is not None else "202"
                log("[demo] got 0x%s expected 0x%s -> %s" %
                    (got, want, "MATCH" if got == want else "MISMATCH"))
            return
        time.sleep(3)
    log("[demo] timeout - engine binary missing or GPU issue")

def selftest():
    ok = True
    key = "0000000000000000000000000000000000000000000000000000000000000008"
    wif = hex_to_wif(key); back = wif_to_hex(wif)
    print("WIF(8)   =", wif); print("WIF->HEX =", back); ok &= back == key
    m = verify_key(key, "1EhqbyUMvvs7BfL8goY6qcPbD6YKfPqb7e")
    print("key 8 -> puzzle#4 addr:", m or "FAIL"); ok &= bool(m)
    pub = pubkey_compressed(bytes.fromhex(key)).hex()
    ok &= pub == "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    ok &= on_curve(pub) and on_curve(KNOWN_PUZZLE_PUB[160])
    print("on_curve ok:", ok)
    lo, hi = parse_keyspace("8000000000000000000000000000000000:ffffffffffffffffffffffffffffffffff", 136)
    print("keyspace normalized -> 0x%x..0x%x" % (lo, hi))
    ok &= lo == 1 << 135 and hi == (1 << 136) - 1
    ph = parse_bitcoin_hash(WALLET_HASH)
    print("bitcoin hash parsed: iters=%d salt=%s" % (ph["iters"], ph["salt"]))
    ok &= ph["iters"] == 99974 and len(ph["mkey"]) == 64 and len(ph["salt"]) == 16
    dec = decode_blob(BLOB_STR)
    print("blob decoded: %d digits" % len(dec)); ok &= len(dec) == 77
    ta = tempfile.NamedTemporaryFile(delete=False); tb = tempfile.NamedTemporaryFile(delete=False)
    ta.write(b"A" * 100 + b"X" * 20 + b"B" * 100); ta.close()
    tb.write(b"A" * 100 + b"Y" * 20 + b"B" * 100); tb.close()
    d = binary_diff(ta.name, tb.name)
    ok &= "1 differing region" in d
    os.unlink(ta.name); os.unlink(tb.name)
    print("binary diff ok:", "1 differing region" in d)
    z = int.from_bytes(sha256d(b"t"), "big")
    sig = _sign(bytes.fromhex(key), z)
    ok &= bool(sig and sig[0] == 0x30)
    print("pure ECDSA sig ok:", ok)
    d2 = bech32_decode("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
    ok &= bool(d2 and convertbits(d2[1], 5, 8, False))
    print("bech32 decode ok:", ok)
    mut = layout_mutants("пароль")
    ok &= any(x == "gfhjkm" for x in mut)
    print("ru->en layout ok:", "gfhjkm" in mut)
    print("analyze sample:", analyze_pub(KNOWN_PUZZLE_PUB[160]).splitlines()[0])
    print("platform:", platform.system(), platform.python_version())
    print("SELFTEST:", "ALL PASS" if ok else "FAILURES")
    return 0 if ok else 1

def bg_launch():
    py = sys.executable
    if IS_WIN:
        alt = os.path.join(os.path.dirname(py), "pythonw.exe")
        if os.path.exists(alt): py = alt
    cmd = [py, os.path.abspath(__file__), "--no-dashboard", "--priority",
           CFG.get("priority", "idle")]
    kw = {"stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL,
          "stderr": subprocess.DEVNULL}
    if IS_WIN:
        kw["creationflags"] = (getattr(subprocess, "DETACHED_PROCESS", 0) |
                               getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) |
                               getattr(subprocess, "CREATE_NO_WINDOW", 0))
        kw["close_fds"] = True
    else:
        kw["start_new_session"] = True
    subprocess.Popen(cmd, **kw)
    print("daemon launched (pid file: %s)" % PID_FILE)

def stop_daemon():
    if not os.path.exists(PID_FILE): print("no pid file"); return 0
    try:
        pid = int(read_text(PID_FILE).strip())
        kill_pid(pid); print("stopped pid %d" % pid)
    except Exception as e:
        print("stop failed: %s" % e)
    try: os.remove(PID_FILE)
    except Exception: pass
    return 0

def install_startup():
    py = sys.executable
    if IS_WIN:
        alt = os.path.join(os.path.dirname(py), "pythonw.exe")
        if os.path.exists(alt): py = alt
    script = os.path.abspath(__file__)
    if IS_WIN:
        tr = '"%s" "%s" --no-dashboard' % (py, script)
        r = subprocess.run(["schtasks", "/create", "/tn", "PuzzleSniper4", "/tr", tr,
                            "/sc", "onlogon", "/rl", "highest", "/f"],
                           capture_output=True, text=True)
        print((r.stdout or r.stderr).strip() or "schtasks done")
    elif IS_MAC:
        plist = os.path.expanduser("~/Library/LaunchAgents/co.hackerai.puzzle_sniper.plist")
        os.makedirs(os.path.dirname(plist), exist_ok=True)
        write_text(plist, """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>co.hackerai.puzzle_sniper</string>
  <key>ProgramArguments</key><array><string>%s</string><string>%s</string>
    <string>--no-dashboard</string></array>
  <key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
</dict></plist>""" % (py, script))
        print("launchd plist written: %s" % plist)
    else:
        line = "@reboot %s %s --no-dashboard >/dev/null 2>&1" % (py, script)
        subprocess.run('(crontab -l 2>/dev/null; echo "%s") | crontab -' % line,
                       shell=True)
        print("crontab @reboot installed")
    print("auto-start installed - engine will launch at logon/reboot")

def uninstall_startup():
    if IS_WIN:
        r = subprocess.run(["schtasks", "/delete", "/tn", "PuzzleSniper4", "/f"],
                           capture_output=True, text=True)
        print((r.stdout or r.stderr).strip() or "schtasks delete done")
    elif IS_MAC:
        plist = os.path.expanduser("~/Library/LaunchAgents/co.hackerai.puzzle_sniper.plist")
        try: os.remove(plist); print("launchd plist removed")
        except Exception: print("no plist found")
    else:
        subprocess.run('crontab -l 2>/dev/null | grep -v "puzzle_sniper" | crontab -',
                       shell=True)
        print("crontab entry removed")

def dashboard_loop():
    while RUNNING[0]:
        try:
            print(SEP); print(status_summary()); print(SEP)
        except Exception:
            pass
        for _ in range(30):
            if not RUNNING[0]: return
            time.sleep(1)

def main():
    global CFG
    ap = argparse.ArgumentParser(
        description="sniper 4.2 - wallet recovery + puzzle engine (stdlib, cross-platform)")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--analyze", metavar="PUBKEY")
    ap.add_argument("--demo", action="store_true")
    ap.add_argument("--demo-bitcrack", action="store_true")
    ap.add_argument("--wallet-scan", metavar="FILE")
    ap.add_argument("--wallet-diff", nargs=2, metavar=("A", "B"))
    ap.add_argument("--noise-scan", metavar="DIR")
    ap.add_argument("--verify-blob", action="store_true")
    ap.add_argument("--snipe-dat", metavar="URL")
    ap.add_argument("--layout-wordlist", nargs=2, metavar=("SRC", "DST"))
    ap.add_argument("--crack", action="store_true")
    ap.add_argument("--interval", type=int, default=0)
    ap.add_argument("--dashboard", action="store_true")
    ap.add_argument("--no-dashboard", action="store_true")
    ap.add_argument("--priority", choices=["idle", "below", "normal"], default="")
    ap.add_argument("--bg", action="store_true")
    ap.add_argument("--stop", action="store_true")
    ap.add_argument("--install-startup", action="store_true")
    ap.add_argument("--uninstall-startup", action="store_true")
    args = ap.parse_args()

    CFG = cfg_load()
    if args.interval: CFG["poll_interval"] = args.interval
    if args.priority: CFG["priority"] = args.priority
    if args.check: sys.exit(selftest())
    if args.analyze: print(analyze_pub(args.analyze)); sys.exit(0)
    if args.wallet_scan: print(wallet_scan_text(args.wallet_scan)); sys.exit(0)
    if args.wallet_diff: print(binary_diff(args.wallet_diff[0], args.wallet_diff[1])); sys.exit(0)
    if args.noise_scan: print(noise_scan_text(args.noise_scan)); sys.exit(0)
    if args.verify_blob: print(verify_blob_text()); sys.exit(0)
    if args.snipe_dat: snipe_dat(args.snipe_dat); sys.exit(0)
    if args.layout_wordlist:
        write_layout_wordlist(args.layout_wordlist[0], args.layout_wordlist[1]); sys.exit(0)
    if args.crack:
        start_crack()
        while CRACK["running"]:
            print("[crack] %s | found=%s" % (CRACK["step"], CRACK["found"] or "-"), flush=True)
            time.sleep(10)
        sys.exit(0)
    if args.stop: sys.exit(stop_daemon())
    if args.install_startup: install_startup(); sys.exit(0)
    if args.uninstall_startup: uninstall_startup(); sys.exit(0)

    # ---- daemon start: heal state, write pid, spawn threads ----------------
    set_priority(CFG.get("priority", "idle"))
    heal_state()
    stale = False
    if os.path.exists(PID_FILE):
        try:
            old = int(read_text(PID_FILE).strip())
            if pid_alive(old) and old != os.getpid():
                log("another instance running (pid %d) - aborting" % old); sys.exit(1)
            if not pid_alive(old): stale = True
        except Exception:
            stale = True
    try: write_text(PID_FILE, str(os.getpid()))
    except Exception: pass
    if stale: log("stale pid cleaned - fresh start")

    if not CFG.get("telegram_token"):
        log("WARNING: no telegram token")
    else:
        tg_autodetect_chat()
        threading.Thread(target=tg_poll_loop, daemon=True).start()

    seed_targets()
    threading.Thread(target=monitor_loop, daemon=True).start()
    threading.Thread(target=engine_loop, daemon=True).start()

    if CFG.get("ping_minutes", 0) > 0:
        def ping():
            last = 0.0
            while RUNNING[0]:
                if time.time() - last > CFG["ping_minutes"] * 60:
                    tg_send("sniper alive - %s" % uptime_str()); last = time.time()
                time.sleep(30)
        threading.Thread(target=ping, daemon=True).start()

    try:
        if args.demo: demo_run(False)
        elif args.demo_bitcrack: demo_run(True)
        else:
            tg_send("<b>SNIPER 4.2 ONLINE</b>\n" + status_summary())
            if args.dashboard:
                dashboard_loop()
            else:
                log("quiet mode - running (CTRL+C to stop); app.log for details")
                while RUNNING[0]: time.sleep(1)
    except KeyboardInterrupt:
        log("interrupted")
    finally:
        RUNNING[0] = False
        kill_active(); stop_crack()
        try: os.remove(PID_FILE)
        except Exception: pass
    sys.exit(0)


setup_console()
CFG = cfg_load()
if __name__ == "__main__":
    main()
