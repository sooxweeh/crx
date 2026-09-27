#!/usr/bin/env python3
"""
=============================================================================
BIP-39 PARTIAL SEED RECOVERY — FOR YOUR OWN WALLET
=============================================================================
Inputs:
  * Words you remember, with their positions (0-indexed)
  * Optional: an address from the wallet (proves you got the right seed)

Method:
  1. Brute-force missing words against the BIP-39 checksum.
  2. For each checksum-valid candidate, derive the m/84'/0'/0'/0/0 address
     (native segwit) using BIP-32/39/84 and compare to your known address.
  3. Print the match.

No network calls. Standard library only. Windows CMD compatible.
=============================================================================
"""

import hashlib
import hmac
import itertools
import sys
import time
from typing import List, Dict, Optional, Tuple

# -----------------------------------------------------------------------------
# BIP-39 wordlist
# -----------------------------------------------------------------------------
try:
    with open("english.txt", "r", encoding="utf-8") as f:
        WORDLIST = [w.strip() for w in f if w.strip()]
    assert len(WORDLIST) == 2048, "wordlist must have 2048 words"
except FileNotFoundError:
    print("ERROR: english.txt not found next to this script.")
    print("Download from: https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt")
    sys.exit(1)

WORD_TO_INDEX = {w: i for i, w in enumerate(WORDLIST)}

# -----------------------------------------------------------------------------
# secp256k1 parameters (pure Python, no external libs)
# -----------------------------------------------------------------------------
P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G  = (Gx, Gy)

def _inv(a, m):
    return pow(a, -1, m)

def _add(P1, P2):
    if P1 is None: return P2
    if P2 is None: return P1
    x1, y1 = P1; x2, y2 = P2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if P1 == P2:
        m = (3 * x1 * x1) * _inv(2 * y1, P) % P
    else:
        m = (y2 - y1) * _inv(x2 - x1, P) % P
    x3 = (m * m - x1 - x2) % P
    y3 = (m * (x1 - x3) - y1) % P
    return (x3, y3)

def _mul(k, Pt):
    R = None
    while k:
        if k & 1:
            R = _add(R, Pt)
        Pt = _add(Pt, Pt)
        k >>= 1
    return R

def pubkey_compressed(priv_int: int) -> bytes:
    x, y = _mul(priv_int, G)
    return bytes([0x02 + (y & 1)]) + x.to_bytes(32, "big")

# -----------------------------------------------------------------------------
# Hashing helpers
# -----------------------------------------------------------------------------
def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def ripemd160(b: bytes) -> bytes:
    h = hashlib.new("ripemd160")
    h.update(b)
    return h.digest()

def hash160(b: bytes) -> bytes:
    return ripemd160(sha256(b))

def b58check(payload: bytes) -> str:
    """Base58Check encoding."""
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    checksum = sha256(sha256(payload))[:4]
    data = payload + checksum
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = alphabet[r] + out
    for byte in data:
        if byte == 0:
            out = "1" + out
        else:
            break
    return out

def bech32_encode(hrp: str, data: List[int]) -> str:
    """Bech32 encoding (BIP-173), for bc1q... addresses."""
    CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    def polymod(values):
        GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
        chk = 1
        for v in values:
            b = chk >> 25
            chk = (chk & 0x1ffffff) << 5 ^ v
            for i in range(5):
                chk ^= GEN[i] if ((b >> i) & 1) else 0
        return chk
    def hrp_expand(h):
        return [ord(x) >> 5 for x in h] + [0] + [ord(x) & 31 for x in h]
    def convertbits(data, frombits, tobits, pad=True):
        acc = 0; bits = 0; ret = []
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
    data5 = convertbits(data, 8, 5)
    combined = hrp_expand(hrp) + data5
    checksum_val = polymod(combined + [0, 0, 0, 0, 0, 0]) ^ 1
    checksum = [(checksum_val >> (5 * (5 - i))) & 31 for i in range(6)]
    return hrp + "1" + "".join(CHARSET[d] for d in data5 + checksum)

# -----------------------------------------------------------------------------
# BIP-39: mnemonic -> seed
# -----------------------------------------------------------------------------
def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    """BIP-39 seed derivation (PBKDF2-HMAC-SHA512, 2048 rounds)."""
    salt = ("mnemonic" + passphrase).encode("utf-8")
    return hashlib.pbkdf2_hmac("sha512", mnemonic.encode("utf-8"), salt, 2048, 64)

def entropy_from_mnemonic(words: List[str]) -> Optional[bytes]:
    """Validate BIP-39 checksum. Returns entropy if valid, else None."""
    try:
        indices = [WORD_TO_INDEX[w] for w in words]
    except KeyError:
        return None
    bits = 0
    for i in indices:
        bits = (bits << 11) | i
    total_bits = len(words) * 11
    entropy_bits = (total_bits * 32) // 33
    checksum_bits = total_bits - entropy_bits
    entropy = (bits >> checksum_bits).to_bytes(entropy_bits // 8, "big")
    expected = sha256(entropy)[0] >> (8 - checksum_bits)
    actual = bits & ((1 << checksum_bits) - 1)
    return entropy if expected == actual else None

# -----------------------------------------------------------------------------
# BIP-32: seed -> extended keys
# -----------------------------------------------------------------------------
def master_key(seed: bytes) -> Tuple[int, bytes]:
    I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    return int.from_bytes(I[:32], "big"), I[32:]

def ckd_priv(k: int, c: bytes, index: int) -> Tuple[int, bytes]:
    """Child key derivation (private)."""
    if index >= 0x80000000:
        data = b"\x00" + k.to_bytes(32, "big") + index.to_bytes(4, "big")
    else:
        data = pubkey_compressed(k) + index.to_bytes(4, "big")
    I = hmac.new(c, data, hashlib.sha512).digest()
    child_k = (int.from_bytes(I[:32], "big") + k) % N
    return child_k, I[32:]

def derive_path(seed: bytes, path: str) -> int:
    """Derive private key at path like m/84'/0'/0'/0/0."""
    k, c = master_key(seed)
    for part in path.split("/")[1:]:
        if part.endswith("'") or part.endswith("h"):
            idx = int(part[:-1]) + 0x80000000
        else:
            idx = int(part)
        k, c = ckd_priv(k, c, idx)
    return k

# -----------------------------------------------------------------------------
# Address derivation
# -----------------------------------------------------------------------------
def address_p2wpkh(priv: int) -> str:
    """Native segwit bc1q... (BIP-84)."""
    return bech32_encode("bc", [0x00] + list(hash160(pubkey_compressed(priv))))

def address_p2pkh(priv: int) -> str:
    """Legacy 1... (BIP-44)."""
    return b58check(b"\x00" + hash160(pubkey_compressed(priv)))

def address_p2sh_p2wpkh(priv: int) -> str:
    """Nested segwit 3... (BIP-49)."""
    redeem = b"\x00\x14" + hash160(pubkey_compressed(priv))
    return b58check(b"\x05" + hash160(redeem))

def derive_addresses(seed: bytes, account: int = 0, change: int = 0, idx: int = 0):
    """Return dict of address types for the given path."""
    paths = {
        "p2pkh  (m/44'/0'/a'/c/i)":  f"m/44'/0'/{account}'/{change}/{idx}",
        "p2sh   (m/49'/0'/a'/c/i)":  f"m/49'/0'/{account}'/{change}/{idx}",
        "p2wpkh (m/84'/0'/a'/c/i)":  f"m/84'/0'/{account}'/{change}/{idx}",
    }
    result = {}
    for label, path in paths.items():
        k = derive_path(seed, path)
        if "p2pkh" in label:
            result[label] = address_p2pkh(k)
        elif "p2sh" in label:
            result[label] = address_p2sh_p2wpkh(k)
        else:
            result[label] = address_p2wpkh(k)
    return result

# -----------------------------------------------------------------------------
# Recovery
# -----------------------------------------------------------------------------
def recover(known: Dict[int, str],
            word_count: int = 12,
            passphrase: str = "",
            target_address: Optional[str] = None,
            max_missing: int = 4) -> Optional[List[str]]:
    """
    known: {position (0-indexed): word}
    passphrase: BIP-39 optional passphrase ("" if none)
    target_address: if provided, verify derivation matches before returning
    """
    missing = [i for i in range(word_count) if i not in known]
    if not missing:
        words = [known[i] for i in range(word_count)]
        return words if entropy_from_mnemonic(words) else None
    if len(missing) > max_missing:
        raise ValueError(
            f"{len(missing)} words missing — search space too large. "
            f"Limit is {max_missing}."
        )

    last_pos = word_count - 1
    middle_missing = [i for i in missing if i != last_pos]
    last_missing = last_pos in missing

    total = (2048 ** len(middle_missing)) * (2048 if last_missing else 1)
    print(f"Search space: {total:,} candidates "
          f"({len(middle_missing)} middle + "
          f"{'1 last' if last_missing else '0 last'} missing)")
    print()

    start_time = time.time()
    tried = 0
    found_checksum_valid = 0

    grids = [WORDLIST] * len(middle_missing)
    for combo in itertools.product(*grids):
        tried += 1
        partial = [None] * word_count
        for pos, w in known.items():
            partial[pos] = w
        for pos, w in zip(middle_missing, combo):
            partial[pos] = w

        last_candidates = WORDLIST if last_missing else [partial[last_pos]]
        for last_word in last_candidates:
            partial[last_pos] = last_word
            if entropy_from_mnemonic(partial) is None:
                continue
            found_checksum_valid += 1
            mnemonic = " ".join(partial)

            if target_address is None:
                _progress(tried, total, start_time, found_checksum_valid)
                return partial[:]

            # Verify against target address
            seed = mnemonic_to_seed(mnemonic, passphrase)
            addrs = derive_addresses(seed)
            if target_address in addrs.values():
                _progress(tried, total, start_time, found_checksum_valid)
                return partial[:]

        if tried % 100_000 == 0:
            _progress(tried, total, start_time, found_checksum_valid)

    _progress(tried, total, start_time, found_checksum_valid)
    return None

def _progress(tried: int, total: int, start: float, valid: int):
    elapsed = time.time() - start
    rate = tried / elapsed if elapsed > 0 else 0
    print(f"  tried {tried:,} / {total:,}  |  "
          f"rate {rate:,.0f}/s  |  "
          f"checksum-valid: {valid}  |  "
          f"elapsed {elapsed:.1f}s")

# -----------------------------------------------------------------------------
# CLI
# -----------------------------------------------------------------------------
def main():
    print("=" * 70)
    print("  BIP-39 PARTIAL SEED RECOVERY — for your own wallet")
    print("=" * 70)
    print()
    print("You will provide the words you remember. Use ? for unknown words.")
    print("Example:  abandon ability able ? about above absent ? absurd abuse access ?")
    print()

    raw = input("Mnemonic (space-separated, ? = unknown): ").strip().lower()
    words = raw.split()
    if len(words) not in (12, 15, 18, 21, 24):
        print(f"ERROR: {len(words)} words — must be 12/15/18/21/24")
        sys.exit(1)

    known = {i: w for i, w in enumerate(words) if w != "?" and w in WORD_TO_INDEX}
    unknown = [i for i, w in enumerate(words) if w not in known]
    print(f"  known:   {len(known)}")
    print(f"  unknown: {len(unknown)} -> positions {unknown}")
    print()

    pp = input("BIP-39 passphrase (Enter if none): ")
    print()

    target = input("Known address from this wallet (Enter to skip): ").strip()
    target = target or None
    if target:
        print(f"  Will verify against: {target}")
    else:
        print("  No address provided — will return first checksum-valid phrase.")
        print("  Provide an address to guarantee you get YOUR seed, not a random valid one.")
    print()

    print("Starting search...")
    print()
    try:
        result = recover(known, word_count=len(words),
                         passphrase=pp, target_address=target)
    except ValueError as e:
        print(f"ERROR: {e}")
        sys.exit(1)

    print()
    print("=" * 70)
    if result:
        print("  RECOVERED:")
        print()
        print("    " + " ".join(result))
        print()
        if target:
            print("  ✓ Verified against your address.")
        else:
            print("  ⚠  Not verified against an address — cross-check before use.")
    else:
        print("  No match found.")
        if target:
            print("  Possible causes:")
            print("    - One of your 'known' words is actually wrong")
            print("    - Wrong passphrase")
            print("    - Address is from a different account/derivation than m/84'/0'/0'/0/0")
    print("=" * 70)
    print()
    print("Press Enter to exit.")
    input()

if __name__ == "__main__":
    main()
