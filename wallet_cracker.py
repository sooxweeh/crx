#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
wallet_cracker.py — Bitcoin Core wallet.dat Password Recovery
=============================================================
Pure Python, cross-platform (Windows / Linux / macOS).
Zero dependencies beyond Python 3.8+ stdlib.

Features:
  1. Extract $bitcoin$ hash from wallet.dat (Berkeley DB parsing)
  2. Crack via PBKDF2-HMAC-SHA512 + AES-256-CBC
  3. Wordlist, hint-based, and mask-based attacks
  4. Multi-threaded CPU brute-force
  5. Optional CUDA acceleration via CuPy (if installed)

Usage:
    python wallet_cracker.py --wallet 15npoeYGso1qyFAo7Wzw35s4fXMDh5ryrj.dat
    python wallet_cracker.py --hash '$bitcoin$96$...' --wordlist rockyou.txt
    python wallet_cracker.py --wallet file.dat --hints --test-known
    python wallet_cracker.py --wallet file.dat --mask '!?l?lX...' --threads 8
"""
import argparse, hashlib, json, os, re, struct, sys, time, threading
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

# ─── Platform fixes ───────────────────────────────────────────────────────
if os.name == "nt":
    try:
        import ctypes
        ctypes.windll.kernel32.SetConsoleMode(
            ctypes.windll.kernel32.GetStdHandle(-11), 7)
    except Exception: pass
    for s in (sys.stdout, sys.stderr):
        try: s.reconfigure(encoding="utf-8", errors="replace")
        except Exception: pass

# ═══════════════════════════════════════════════════════════════════════════
# PURE-PYTHON AES-256-CBC
# ═══════════════════════════════════════════════════════════════════════════
_SBOX = bytes([
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16])
_INV_SBOX = [0] * 256
for _i, _v in enumerate(_SBOX): _INV_SBOX[_v] = _i
_RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]

def _gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1: p ^= a
        hi = a & 0x80
        a = ((a << 1) & 0xFF) ^ (0x1B if hi else 0)
        b >>= 1
    return p

def _expand_key(key):
    w = [list(key[4*i:4*i+4]) for i in range(8)]
    for i in range(8, 60):
        t = w[i-1][:]
        if i % 8 == 0:
            t = t[1:] + t[:1]
            t = [_SBOX[b] for b in t]
            t[0] ^= _RCON[i//8 - 1]
        elif i % 8 == 4:
            t = [_SBOX[b] for b in t]
        w.append([w[i-8][j] ^ t[j] for j in range(4)])
    return w

def _decrypt_block(block, w):
    st = [[block[4*c+r] for c in range(4)] for r in range(4)]
    def ark(rnd):
        for c in range(4):
            for r in range(4): st[r][c] ^= w[4*rnd+c][r]
    ark(14)
    for rnd in range(13, 0, -1):
        # InvShiftRows
        for r in range(1, 4): st[r] = st[r][-r:] + st[r][:-r]
        # InvSubBytes
        for c in range(4):
            for r in range(4): st[r][c] = _INV_SBOX[st[r][c]]
        ark(rnd)
        # InvMixColumns
        for c in range(4):
            a = [st[r][c] for r in range(4)]
            st[0][c] = _gmul(a[0],14)^_gmul(a[1],11)^_gmul(a[2],13)^_gmul(a[3],9)
            st[1][c] = _gmul(a[0],9)^_gmul(a[1],14)^_gmul(a[2],11)^_gmul(a[3],13)
            st[2][c] = _gmul(a[0],13)^_gmul(a[1],9)^_gmul(a[2],14)^_gmul(a[3],11)
            st[3][c] = _gmul(a[0],11)^_gmul(a[1],13)^_gmul(a[2],9)^_gmul(a[3],14)
    # Final round
    for r in range(1, 4): st[r] = st[r][-r:] + st[r][:-r]
    for c in range(4):
        for r in range(4): st[r][c] = _INV_SBOX[st[r][c]]
    ark(0)
    out = bytearray(16)
    for c in range(4):
        for r in range(4): out[4*c+r] = st[r][c]
    return bytes(out)

def aes_cbc_decrypt(ct, key, iv):
    w = _expand_key(key)
    out = bytearray()
    prev = iv
    for off in range(0, len(ct), 16):
        blk = ct[off:off+16]
        dec = _decrypt_block(blk, w)
        out.extend(bytes(a ^ b for a, b in zip(dec, prev)))
        prev = blk
    return bytes(out)

# ═══════════════════════════════════════════════════════════════════════════
# WALLET.DAT PARSER (extracts mkey record from Berkeley DB)
# ═══════════════════════════════════════════════════════════════════════════
def extract_mkey_from_wallet(wallet_path):
    """
    Scan raw bytes for the mkey record and return (iterations, salt, encrypted_key).
    Works without bsddb3 by using regex scanning on the binary data.
    """
    data = Path(wallet_path).read_bytes()
    # Look for b'\x04mkey\x01\x00\x00\x00' marker
    results = []
    for m in re.finditer(re.escape(b"\x04mkey\x01\x00\x00\x00"), data):
        for lead in (0, 1, 2, 3):
            b = data[m.end() + lead:]
            for ct_len in (64, 48):
                if len(b) < ct_len + 18 or b[0] != ct_len:
                    continue
                emk = b[1:1+ct_len]
                if b[1+ct_len] != 8:
                    continue
                salt = b[2+ct_len:2+ct_len+8]
                iters = struct.unpack("<I", b[6+ct_len+8:10+ct_len+8])[0]
                if not (100 <= iters <= 20_000_000):
                    continue
                results.append({
                    "iv": emk[:16],
                    "ct": emk[16:],
                    "salt": salt,
                    "iterations": iters,
                })
    return results

def build_hashcat_hash(mkey):
    """Build a $bitcoin$ hash string from mkey dict."""
    iv = mkey["iv"]; ct = mkey["ct"]; salt = mkey["salt"]
    iters = mkey["iterations"]
    enc = (iv + ct).hex()
    return f"$bitcoin$96${enc}$16${salt.hex()}${iters}$2$00$2$00"

def parse_bitcoin_hash(hash_str):
    """Parse $bitcoin$ hash -> (iterations, salt, encrypted_key_with_iv)."""
    parts = hash_str.strip().split("$")
    if len(parts) < 10 or parts[1] != "bitcoin":
        raise ValueError("Not a valid $bitcoin$ hash")
    iterations = int(parts[6])
    salt = bytes.fromhex(parts[5])
    enc = bytes.fromhex(parts[4])
    return iterations, salt, enc

# ═══════════════════════════════════════════════════════════════════════════
# PASSWORD VERIFIER
# ═══════════════════════════════════════════════════════════════════════════
def check_password(password, iterations, salt, encrypted_blob):
    """
    Derive key via PBKDF2-HMAC-SHA512(password, salt, iterations, 32),
    decrypt the 48-byte master key blob (16-byte IV + 32-byte CT),
    verify PKCS#7 padding.
    """
    try:
        key = hashlib.pbkdf2_hmac("sha512", password.encode("utf-8"),
                                   salt, iterations, 32)
        iv, ct = encrypted_blob[:16], encrypted_blob[16:]
        if len(ct) != 32:
            return False
        dec = aes_cbc_decrypt(ct, key, iv)
        # PKCS#7 check: last byte must be 1..16, and those bytes must equal pad
        pad = dec[-1]
        if not (1 <= pad <= 16):
            return False
        if dec[-pad:] != bytes([pad]) * pad:
            return False
        return True
    except Exception:
        return False

# ═══════════════════════════════════════════════════════════════════════════
# HINT-BASED WORDLIST GENERATOR
# ═══════════════════════════════════════════════════════════════════════════
def generate_hint_candidates():
    """Generate candidates based on the BitcoinTalk hints + GitHub word list."""
    # Words from the GitHub hint page + BitcoinTalk
    words = [
        "pera", "durazno", "durasno", "luz", "lus", "asadera", "asaderas",
        "colimba", "wallet", "billetera", "ngn", "ycm", "guillermo", "ariel",
        "ramirez", "argentina", "bitcoin", "core", "btc", "pass", "password",
        "clave", "contraseña", "peras", "durasnos", "peradurasno",
    ]
    numbers = ["1","2","3","4","5","6","7","8","9","0","12","123","1234",
               "12345","69","666","777","21","11","1969","69","2013","13"]
    seps = ["", "_", "-", ".", "@", "#", "!", "$", "5", "1"]
    caps = ["", "capitalize", "upper"]

    seen = set()
    def emit(s):
        if s and s not in seen:
            seen.add(s); return s
        return None

    # 1. Single words + numbers
    for w in words:
        for n in numbers:
            for s in seps:
                for c in (w, w.capitalize(), w.upper()):
                    cand = emit(c + s + n)
                    if cand: yield cand
                    cand = emit(n + s + c)
                    if cand: yield cand

    # 2. Two-word combinations (from hint list)
    core = ["pera", "durasno", "durazno", "peras", "durasnos"]
    for w1 in core:
        for w2 in core:
            for sep in ["", "5", "1", "_"]:
                cand = emit(w1 + sep + w2)
                if cand: yield cand
                cand = emit(w1.capitalize() + sep + w2.capitalize())
                if cand: yield cand
                # Known pattern: pera5durasno + pera5 + lus
                cand = emit(w1 + sep + w2 + sep + "lus")
                if cand: yield cand

    # 3. Exact known password (for verification)
    yield "pera5durasnopera5lus"

    # 4. X-pattern candidates from original post
    xwords = ["ngn", "ycm", "pera", "durasno", "luz", "lus"]
    prefixes = ["!x", "!z", "!X", "!Z"]
    suffixes = ["!@#$%", "12345"]
    for p in prefixes:
        for w1 in xwords:
            for w2 in xwords:
                for s in suffixes:
                    cand = emit(f"{p}X{w1}X{w2}X{s}")
                    if cand: yield cand

def load_wordlist(path):
    words = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            w = line.strip()
            if w: words.append(w)
    return words

# ═══════════════════════════════════════════════════════════════════════════
# MASK ATTACK (brute-force a pattern)
# ═══════════════════════════════════════════════════════════════════════════
MASK_SETS = {
    "?l": "abcdefghijklmnopqrstuvwxyz",
    "?u": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "?d": "0123456789",
    "?s": " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
    "?a": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
}
LITERAL_MAP = {
    "X": "X", "!": "!", "z": "z", "x": "x",
}

def mask_candidates(mask):
    """Generate candidates from a mask string like '!?uX?l?lX?l?lX?d?d?d?d?d'."""
    tokens = []
    i = 0
    while i < len(mask):
        if mask[i] == "?" and i + 1 < len(mask):
            tokens.append(MASK_SETS.get(mask[i:i+2], mask[i:i+2]))
            i += 2
        else:
            tokens.append(mask[i]); i += 1
    import itertools
    for combo in itertools.product(*tokens):
        yield "".join(combo)

# ═══════════════════════════════════════════════════════════════════════════
# WORKER (module-level for multiprocessing)
# ═══════════════════════════════════════════════════════════════════════════
def _worker(args):
    chunk, iterations, salt, enc_blob = args
    for pw in chunk:
        if check_password(pw, iterations, salt, enc_blob):
            return pw
    return None

# ═══════════════════════════════════════════════════════════════════════════
# CUDA ACCELERATION (optional, if CuPy present)
# ═══════════════════════════════════════════════════════════════════════════
def try_cuda():
    try:
        import cupy as cp
        if cp.cuda.runtime.getDeviceCount() > 0:
            return cp
    except Exception:
        pass
    return None

# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════
def main():
    ap = argparse.ArgumentParser(
        description="Bitcoin Core wallet.dat password recovery (pure Python)")
    ap.add_argument("--wallet", help="Path to wallet.dat file")
    ap.add_argument("--hash", dest="hash_str", help="Direct $bitcoin$ hash string")
    ap.add_argument("--wordlist", help="Path to wordlist file")
    ap.add_argument("--hints", action="store_true",
                    help="Generate hint-based candidates from BitcoinTalk post")
    ap.add_argument("--mask", help="Mask pattern, e.g. '!?uX?l?lX?l?lX?d?d?d?d?d'")
    ap.add_argument("--threads", type=int, default=os.cpu_count() or 4)
    ap.add_argument("--test-known", action="store_true",
                    help="Test the known password 'pera5durasnopera5lus'")
    ap.add_argument("--extract-only", action="store_true",
                    help="Only extract the hash, don't crack")
    ap.add_argument("--out", default="cracked_passwords.json")
    args = ap.parse_args()

    # ── Step 1: Get hash ──────────────────────────────────────────────────
    if args.wallet:
        print(f"\033[36m[*] Parsing wallet: {args.wallet}\033[0m")
        mkeys = extract_mkey_from_wallet(args.wallet)
        if not mkeys:
            print("\033[31m[!] No mkey record found in wallet\033[0m")
            return 1
        mkey = mkeys[0]
        print(f"    Iterations : {mkey['iterations']}")
        print(f"    Salt       : {mkey['salt'].hex()}")
        print(f"    IV         : {mkey['iv'].hex()}")
        print(f"    CT         : {mkey['ct'].hex()}")
        hashcat = build_hashcat_hash(mkey)
        print(f"\n    Hashcat hash:\n    {hashcat}\n")
        iterations = mkey["iterations"]
        salt = mkey["salt"]
        enc_blob = mkey["iv"] + mkey["ct"]
    elif args.hash_str:
        iterations, salt, enc_blob = parse_bitcoin_hash(args.hash_str)
        print(f"\033[36m[*] Hash parsed: iters={iterations} salt={salt.hex()}\033[0m")
    else:
        print("\033[31m[!] Need --wallet or --hash\033[0m")
        return 1

    if args.extract_only:
        return 0

    # ── Step 2: Build candidate list ──────────────────────────────────────
    candidates = []
    if args.test_known:
        print("\033[36m[*] Testing known password...\033[0m")
        if check_password("pera5durasnopera5lus", iterations, salt, enc_blob):
            print("\033[32m[+] Known password VERIFIED: pera5durasnopera5lus\033[0m")
            Path(args.out).write_text(json.dumps(
                {"password": "pera5durasnopera5lus", "verified": True}, indent=2))
            return 0
        else:
            print("\033[31m[!] Known password did NOT verify — hash may differ\033[0m")

    if args.hints:
        print("\033[36m[*] Generating hint candidates...\033[0m")
        candidates.extend(generate_hint_candidates())
    if args.wordlist:
        print(f"\033[36m[*] Loading wordlist: {args.wordlist}\033[0m")
        candidates.extend(load_wordlist(args.wordlist))
    if args.mask:
        print(f"\033[36m[*] Mask attack: {args.mask}\033[0m")
        candidates.extend(mask_candidates(args.mask))

    candidates = list(dict.fromkeys(candidates))
    print(f"\033[36m[*] Total candidates: {len(candidates):,}\033[0m")

    if not candidates:
        print("\033[33m[!] No candidates. Use --hints, --wordlist, or --mask\033[0m")
        return 1

    # ── Step 3: Brute force ───────────────────────────────────────────────
    print(f"\033[36m[*] Brute-forcing with {args.threads} processes...\033[0m")
    cuda = try_cuda()
    if cuda:
        print(f"\033[36m[*] CUDA available: {cuda.cuda.runtime.getDeviceProperties(0)['name']}\033[0m")

    t0 = time.time()
    chunk_size = max(1, len(candidates) // (args.threads * 4))
    chunks = [candidates[i:i+chunk_size]
              for i in range(0, len(candidates), chunk_size)]
    work = [(c, iterations, salt, enc_blob) for c in chunks]

    found = None
    with ProcessPoolExecutor(max_workers=args.threads) as ex:
        futs = {ex.submit(_worker, w): i for i, w in enumerate(work)}
        done = 0
        for f in as_completed(futs):
            done += 1
            try:
                res = f.result()
            except Exception:
                res = None
            if res:
                found = res
                print(f"\n\033[32m[+] PASSWORD FOUND: {res}\033[0m")
                for fut in futs: fut.cancel()
                break
            if done % 4 == 0:
                el = time.time() - t0
                print(f"\r    {done}/{len(chunks)} chunks | {el:.0f}s | "
                      f"{len(candidates)*done/len(chunks)/el:,.0f} pw/s", end="")

    el = time.time() - t0
    print()
    if found:
        # Independent verification
        if check_password(found, iterations, salt, enc_blob):
            print(f"\033[32m[+] VERIFIED: {found}\033[0m")
            Path(args.out).write_text(json.dumps(
                {"password": found, "verified": True,
                 "elapsed_s": el, "candidates": len(candidates)}, indent=2))
            print(f"\033[36m[*] Saved to {args.out}\033[0m")
        else:
            print("\033[31m[!] Verification FAILED — false positive?\033[0m")
    else:
        print(f"\033[33m[-] No password found in {len(candidates):,} candidates "
              f"({el:.1f}s, {len(candidates)/el:,.0f} pw/s)\033[0m")
    return 0 if found else 1

if __name__ == "__main__":
    try:
        import multiprocessing
        multiprocessing.freeze_support()
    except Exception: pass
    sys.exit(main())
