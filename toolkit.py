#!/usr/bin/env python3
"""
OFFLINE TOOLKIT - self-contained Bitcoin address / balance / seed-search utility.

Design constraints:
  * ENTIRELY OFFLINE. Every command works on SUPPLIED DATA (files you pass in) or
    on AUTO-GENERATED data (synthetic datasets from `gendata`, deterministic tests).
  * Network use is opt-in and isolated to the single `scan` command; --offline
    makes it read a previously cached result file instead.

Commands
  selftest   validate the crypto core offline against known vectors
  gendata    auto-generate a synthetic dataset (mnemonics + expected addresses)
  derive     derive addresses from mnemonic / zpub / account pubkey (offline)
  verify     check a candidate mnemonic against target addresses/keyhashes (offline)
  brute      checksum-pruned BIP39 seed search (offline, checkpointed, resumable)
  scan       balance / UTXO lookup for a target list (network; --offline = cache)
  psbt       decode + audit a PSBT file (offline)
  render     write Markdown + HTML reports from results/checkpoints (offline)

NOT implemented (wallet-compromise capabilities): wallet.dat password cracking,
nonce forensics, hardware-wallet sweeping, transaction signing/broadcasting.
This tool is read-only with respect to funds.

Deps: Python 3.8+ stdlib. Uses `coincurve` if present (fast); pure-Python
fallback included so it runs on a bare interpreter with no packages/network.

CROSS-PLATFORM NOTES (Windows / macOS / Linux):
  * All file I/O is explicit UTF-8 with '\n' newlines; no locale guessing.
  * Console output is pure ASCII (a Windows cp1252 console raises
    UnicodeEncodeError on arrows/em-dashes, so none are emitted).
  * Paths are built with os.path.join; no shell utilities, no POSIX-only calls.
  * Multiprocessing follows the spawn-safe pattern: workers are module-level
    functions, main() is guarded by if __name__ == '__main__', and
    freeze_support() is called for frozen/bundled interpreters (PyInstaller).
  * Ctrl+C during a search prints the resume position and exits cleanly.
"""
import argparse
import base64
import hashlib
import hmac
import json
import multiprocessing
import os
import struct
import sys
import time

# ============================================================ secp256k1
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

try:
    import coincurve
    HAVE_COINCURVE = True
except ImportError:
    HAVE_COINCURVE = False


def _inv(a, m=P):
    return pow(a, m - 2, m)


def point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        lam = 3 * x1 * x1 * _inv(2 * y1) % P
    else:
        lam = (y2 - y1) * _inv(x2 - x1) % P
    x3 = (lam * lam - x1 - x2) % P
    return (x3, (lam * (x1 - x3) - y1) % P)


def point_mul(k, pt=G):
    k %= N
    r = None
    while k:
        if k & 1:
            r = point_add(r, pt)
        pt = point_add(pt, pt)
        k >>= 1
    return r


def point_decompress(pub):
    x = int.from_bytes(pub[1:33], 'big')
    a = (pow(x, 3, P) + 7) % P
    y = pow(a, (P + 1) // 4, P)
    if (y & 1) != (pub[0] & 1):
        y = P - y
    if (y * y) % P != a:
        raise ValueError('point not on curve')
    return (x, y)


def compress(pt):
    return bytes([2 + (pt[1] & 1)]) + pt[0].to_bytes(32, 'big')


def priv_to_pub(key32):
    """Compressed pubkey for a 32-byte private key (coincurve if available)."""
    if HAVE_COINCURVE:
        return coincurve.PrivateKey(key32).public_key.format(compressed=True)
    return compress(point_mul(int.from_bytes(key32, 'big')))


# ============================================================ base58 / bech32
B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]


def hash160(b):
    return hashlib.new('ripemd160', hashlib.sha256(b).digest()).digest()


def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def b58decode(s):
    n = 0
    for c in s:
        n = n * 58 + B58.index(c)
    raw = n.to_bytes((n.bit_length() + 7) // 8, 'big') if n else b''
    pad = 0
    for c in s:
        if c == '1':
            pad += 1
        else:
            break
    return b'\x00' * pad + raw


def b58check_decode(s):
    raw = b58decode(s)
    if sha256d(raw[:-4])[:4] != raw[-4:]:
        raise ValueError('bad base58check checksum')
    return raw[:-4]


def _b58check(payload):
    raw = payload + sha256d(payload)[:4]
    n = int.from_bytes(raw, 'big')
    s = ''
    while n:
        n, r = divmod(n, 58)
        s = B58[r] + s
    pad = 0
    for b in raw:
        if b == 0:
            pad += 1
        else:
            break
    return '1' * pad + s


def _polymod(vals):
    chk = 1
    for v in vals:
        b = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            if (b >> i) & 1:
                chk ^= GEN[i]
    return chk


def _hrp_expand(hrp):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _create_checksum(hrp, data):
    pm = _polymod(_hrp_expand(hrp) + data + [0] * 6) ^ 1
    return [(pm >> 5 * (5 - i)) & 31 for i in range(6)]


def _convertbits(data, frombits, tobits, pad=True):
    acc = bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for b in data:
        acc = (acc << frombits) | b
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    return ret


def bech32_encode(hrp, witver, witprog):
    data = [witver] + _convertbits(witprog, 8, 5)
    return hrp + '1' + ''.join(CHARSET[d] for d in data + _create_checksum(hrp, data))


def bech32_decode_witness(addr):
    """bech32 v0 address -> witness program bytes (P2WPKH => keyhash)."""
    if not addr.startswith('bc1'):
        raise ValueError('not a mainnet bech32 address')
    vals = [CHARSET.index(c) for c in addr[3:]]
    data_vals = vals[:-6]
    if data_vals[0] != 0:
        raise ValueError('unsupported witness version')
    return bytes(_convertbits(data_vals[1:], 5, 8, pad=False))


def addr_of_keyhash(kh_hex, kind='p2wpkh'):
    kh = bytes.fromhex(kh_hex)
    if kind == 'p2wpkh':
        return bech32_encode('bc', 0, kh)
    if kind == 'p2pkh':
        return _b58check(b'\x00' + kh)
    if kind == 'p2sh':
        return _b58check(b'\x05' + kh)
    raise ValueError(kind)


# ============================================================ BIP32 / BIP39
def bip32_master(seed):
    I = hmac.new(b'Bitcoin seed', seed, hashlib.sha512).digest()
    return I[:32], I[32:]


def ckd_priv(key, chain, index):
    data = b'\x00' + key + struct.pack('>I', index)
    I = hmac.new(chain, data, hashlib.sha512).digest()
    child = (int.from_bytes(I[:32], 'big') + int.from_bytes(key, 'big')) % N
    return child.to_bytes(32, 'big'), I[32:]


def ckd_pub(pub, chain, index):
    I = hmac.new(chain, pub + struct.pack('>I', index), hashlib.sha512).digest()
    IL = int.from_bytes(I[:32], 'big')
    if IL >= N:
        raise ValueError('invalid IL')
    if HAVE_COINCURVE:
        q = point_decompress(coincurve.PrivateKey(I[:32]).public_key.format(compressed=True))
    else:
        q = point_mul(IL)
    return compress(point_add(point_decompress(pub), q)), I[32:]


def mnemonic_to_seed(mn, passphrase=''):
    return hashlib.pbkdf2_hmac('sha512', mn.encode(), ('mnemonic' + passphrase).encode(), 2048)


def account_keys(seed, purpose=84, account=0, coin=0):
    """Private key + chain code at m/purpose'/coin'/account'."""
    key, chain = bip32_master(seed)
    for idx in (purpose + 0x80000000, coin + 0x80000000, account + 0x80000000):
        key, chain = ckd_priv(key, chain, idx)
    return key, chain


ZPUB_V = 0x04b24746
XPUB_V = 0x0488b21e
VPUB_V = 0x045f1cf6


def ext_key_decode(s):
    raw = b58check_decode(s)
    ver = int.from_bytes(raw[:4], 'big')
    return ver, raw[13:45], raw[45:78]  # version, chaincode, pubkey


def derive_children(pub, chain, count):
    """Yield (index, keyhash_hex, p2wpkh_addr) for external children 0..count-1."""
    for i in range(count):
        child, _cchain = ckd_pub(pub, chain, i)
        kh = hash160(child).hex()
        yield i, kh, addr_of_keyhash(kh)


def account_pubkeys(seed, paths):
    """paths: list of (purpose, coin, account) -> [(label, chaincode, pubkey)]."""
    out = []
    for purpose, coin, account in paths:
        key, chain = account_keys(seed, purpose, coin, account)
        out.append((f"m/{purpose}'/{coin}'/{account}'", chain, priv_to_pub(key)))
    return out


# ============================================================ targets
DEFAULT_TARGETS = {
    "label": "kwikbit-prizes",
    "addresses": [
        "bc1qj7znl49az8jt8j4u9lcp6lhq6xwnm873kvj02c",
        "bc1qnmwral2ucdj6nxfeartpw55vxx7rdf3awljt9h",
        "bc1qxjwe85t3qa7t9qg06klzgtmtr3j4mcdnxek0fd",
    ],
    "keyhashes": [],
    "paths": [[84, 0, 0]],
    "children": 20,
}


def load_targets(path=None):
    if path and os.path.exists(path):
        with open(path, encoding='utf-8') as f:
            t = json.load(f)
        t.setdefault('addresses', [])
        t.setdefault('keyhashes', [])
        t.setdefault('paths', [[84, 0, 0]])
        t.setdefault('children', 20)
        t.setdefault('label', os.path.basename(path))
        return t
    return dict(DEFAULT_TARGETS)


def target_keyhashes(targets):
    khs = []
    for a in targets.get('addresses', []):
        try:
            khs.append(bech32_decode_witness(a).hex())
        except Exception:
            pass
    khs += [k.lower() for k in targets.get('keyhashes', [])]
    return sorted(set(khs))


def child_addresses_for_seed(seed, targets):
    """Candidate child addresses for a seed under the target path set."""
    found = []
    khs = set(target_keyhashes(targets))
    for label, chain, pub in account_pubkeys(seed, [tuple(p) for p in targets['paths']]):
        for i, kh, addr in derive_children(pub, chain, int(targets['children'])):
            if kh in khs:
                found.append((label, i, kh, addr))
    return found


# ============================================================ wordlist / search
def ensure_wordlist(path='english.txt'):
    if os.path.exists(path) and os.path.getsize(path) > 10000:
        with open(path, encoding='utf-8') as f:
            wl = f.read().split()
        if len(wl) == 2048:
            return wl
    raise SystemExit(f'BIP39 wordlist not found at {path} (need all 2048 words)')


def last_word_candidates(indices11, wl):
    """The 128 checksum-valid 12th-word indices for a fixed first 11 words."""
    bits_int = 0
    for idx in indices11:
        bits_int = (bits_int << 11) | idx
    prefix15 = (bits_int >> 1).to_bytes(15, 'big')
    hi = (bits_int & 1) << 7
    out = []
    for b7 in range(128):
        ent = prefix15 + bytes([hi | b7])
        h = hashlib.sha256(ent).digest()[0] >> 4
        out.append((b7 << 4) | h)
    return out


def gen_candidates(known_indices, unknown_ix, wl, checkpoint=None, limit=0,
                   log_interval=200000):
    """Stream mnemonic strings: known words + 3 unknown slots (checksum-pruned).

    unknown_ix: BIP39 wordlist indices allowed in the unknown positions.
    Default (all 2048) => 536,870,912 candidates. Checkpointed/resumable.
    """
    subset = set(unknown_ix)
    total = max(1, len(unknown_ix) ** 3 // 16)
    start_pi9 = start_pi10 = count = 0
    if checkpoint and os.path.exists(checkpoint):
        try:
            with open(checkpoint, encoding='utf-8') as f:
                st = json.load(f)
            if st.get('subset', 0) == len(unknown_ix):
                count = st.get('count', 0)
                i9, i10 = st.get('i9'), st.get('i10')
                if i9 in subset and i10 in subset:
                    start_pi9 = unknown_ix.index(i9)
                    start_pi10 = unknown_ix.index(i10)
                print(f'  resume: pi9={start_pi9} pi10={start_pi10} ({count:,} done)')
        except Exception as e:
            print(f'  checkpoint unreadable ({e}); starting fresh')
    t0 = time.time()
    first = True
    pi9 = start_pi9
    while pi9 < len(unknown_ix):
        i9 = unknown_ix[pi9]
        pi10_from = start_pi10 if first else 0
        first = False
        for pi10 in range(pi10_from, len(unknown_ix)):
            i10 = unknown_ix[pi10]
            base = known_indices + [i9, i10]
            for i11 in last_word_candidates(base, wl):
                if i11 not in subset:
                    continue
                count += 1
                if checkpoint and count % 100000 == 0:
                    with open(checkpoint, 'w', encoding='utf-8', newline='\n') as f:
                        json.dump({'i9': i9, 'i10': i10, 'count': count,
                                   'subset': len(unknown_ix)}, f)
                if count % log_interval == 0:
                    el = max(time.time() - t0, 0.001)
                    rate = count / el
                    print(f'  [{time.strftime("%H:%M:%S")}] {count:,} candidates '
                          f'({rate:.0f}/s, ETA {(total - count) / rate / 3600:.1f}h)',
                          flush=True)
                if limit and count >= limit:
                    return
                yield ' '.join(wl[j] for j in base + [i11])
        pi9 += 1


# ============================================================ commands
def cmd_selftest(args):
    """Validate the crypto core offline against known vectors."""
    ok = True
    checks = []

    def check(name, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        checks.append((name, good, str(got)[:70], str(want)[:70]))

    check('bech32 BIP173 vector',
          bech32_encode('bc', 0, bytes.fromhex('751e76e8199196d454941c45d1b3a323f1433bd6')),
          'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4')
    check('secp256k1 1*G',
          hex(point_mul(1)[0]),
          hex(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798))
    mn = ('abandon abandon abandon abandon abandon abandon abandon abandon '
          'abandon abandon abandon about')
    seed = mnemonic_to_seed(mn)
    key, chain = account_keys(seed, 84, 0)
    check('BIP84 account pubkey', priv_to_pub(key).hex(),
          '02707a62fdacc26ea9b63b1c197906f56ee0180d0bcf1966e1a2da34f5f3a09a9b')
    child, _ = ckd_pub(priv_to_pub(key), chain, 0)
    check('BIP84 first address',
          addr_of_keyhash(hash160(child).hex()),
          'bc1q8vph849lf3e9rrj85hsxrzlv949rtahe794k6p')
    a = 'bc1qj7znl49az8jt8j4u9lcp6lhq6xwnm873kvj02c'
    check('address <-> keyhash round trip', addr_of_keyhash(bech32_decode_witness(a).hex()), a)
    wl = ensure_wordlist(args.wordlist)
    known = [wl.index(w) for w in ['visa', 'ivory', 'old', 'captain', 'magnet',
                                   'adapt', 'produce', 'pumpkin', 'demand']]
    check('checksum prune = 128 last words', len(last_word_candidates(known + [0, 0], wl)), 128)

    # end-to-end synthetic hunt (auto-generated data, no network)
    subset = sorted({0, 1, 2, 3, 4, 12, 20, 33, 44})
    phrase = None
    for i11 in last_word_candidates(known + [2, 3], wl):
        if i11 in subset:
            phrase = ' '.join(wl[j] for j in known + [2, 3, i11])
            break
    sd = mnemonic_to_seed(phrase)
    k2, c2 = account_keys(sd, 84, 0)
    ch, _ = ckd_pub(priv_to_pub(k2), c2, 1)
    want_kh = hash160(ch).hex()
    hit = None
    for mn_cand in gen_candidates(known, subset, wl, limit=200000):
        sd2 = mnemonic_to_seed(mn_cand)
        k3, c3 = account_keys(sd2, 84, 0)
        ch2, _ = ckd_pub(priv_to_pub(k3), c3, 1)
        if hash160(ch2).hex() == want_kh:
            hit = mn_cand
            break
    check('synthetic BIP39 hunt (offline)', hit, phrase)

    print('SELFTEST')
    for name, good, got, want in checks:
        print(f"  [{'PASS' if good else 'FAIL'}] {name}")
        if not good:
            print(f'         got : {got}')
            print(f'         want: {want}')
    print(f"  coincurve: {'yes (fast path)' if HAVE_COINCURVE else 'no (pure-python)'}")
    print('RESULT:', 'PASS' if ok else 'FAIL')
    return 0 if ok else 1


def cmd_gendata(args):
    """Auto-generate a synthetic dataset offline: mnemonics + expected addresses."""
    wl = ensure_wordlist(args.wordlist)
    base = [wl.index(w) for w in ['legal', 'winner', 'sheriff', 'require', 'crystal',
                                  'faculty', 'rescue', 'grace', 'maximum']]
    items = []
    for n in range(args.count):
        i9, i10 = n % 2048, (n * 7 + 11) % 2048
        for i11 in last_word_candidates(base + [i9, i10], wl):
            mn = ' '.join(wl[j] for j in base + [i9, i10, i11])
            break
        sd = mnemonic_to_seed(mn)
        k, c = account_keys(sd, 84, 0)
        pub = priv_to_pub(k)
        addrs = [addr for _i, _kh, addr in derive_children(pub, c, args.children)]
        items.append({'mnemonic': mn, 'addresses': addrs})
    with open(args.out, 'w', encoding='utf-8', newline='\n') as f:
        json.dump({'generated': time.strftime('%Y-%m-%dT%H:%M:%S'),
                   'count': args.count, 'items': items}, f, indent=1)
    print(f'wrote {args.count} synthetic items to {args.out}')
    return 0


def _parse_paths(spec):
    out = []
    for p in spec.split(','):
        parts = [int(x) for x in p.split('/')]
        while len(parts) < 3:
            parts.append(0)
        out.append(parts[:3])
    return out


def cmd_derive(args):
    """Derive addresses offline from a mnemonic, zpub/xpub, or account key."""
    rows = []
    if args.mnemonic:
        wl = ensure_wordlist(args.wordlist)
        bad = [w for w in args.mnemonic.split() if w not in wl]
        if bad:
            print(f'  warning: not BIP39 words: {bad}')
        seed = mnemonic_to_seed(args.mnemonic, args.passphrase or '')
        for purpose, coin, account in _parse_paths(args.paths):
            k, c = account_keys(seed, purpose, coin, account)
            pub = priv_to_pub(k)
            for i, kh, addr in derive_children(pub, c, args.children):
                rows.append((f"m/{purpose}'/{coin}'/{account}'/0/{i}", addr, kh))
    elif args.zpub or args.xpub:
        s = args.zpub or args.xpub
        ver, chain, pub = ext_key_decode(s)
        label = {ZPUB_V: 'zpub', XPUB_V: 'xpub', VPUB_V: 'vpub'}.get(ver, hex(ver))
        print(f'  extended key: {label} | chain {chain.hex()[:16]}... | pub {pub.hex()[:16]}...')
        for branch in (0, 1):
            bpub, bchain = ckd_pub(pub, chain, branch)
            for i, kh, addr in derive_children(bpub, bchain, args.children):
                rows.append((f'/{branch}/{i}', addr, kh))
    else:
        print('need --mnemonic or --zpub/--xpub')
        return 2
    print(f'{len(rows)} addresses:')
    for path, addr, kh in rows[:args.limit or len(rows)]:
        print(f'  {path:<26} {addr}  kh={kh[:12]}...')
    if args.json:
        with open(args.json, 'w', encoding='utf-8', newline='\n') as f:
            json.dump([{'path': p, 'address': a, 'keyhash': k} for p, a, k in rows], f, indent=1)
        print(f'wrote {args.json}')
    return 0


def cmd_verify(args):
    """Check candidate mnemonic(s) offline against the target set."""
    targets = load_targets(args.targets)
    khs = set(target_keyhashes(targets))
    print(f'targets: {targets.get("label")} | {len(khs)} keyhashes | '
          f'paths {targets["paths"]} | children 0..{int(targets["children"]) - 1}')
    cands = []
    if args.mnemonic:
        cands.append(args.mnemonic)
    if args.file:
        with open(args.file, encoding='utf-8') as f:
            cands += [l.strip() for l in f if l.strip()]
    if not cands:
        print('need --mnemonic or --file')
        return 2
    hits = 0
    for mn in cands:
        seed = mnemonic_to_seed(mn, args.passphrase or '')
        for label, chain, pub in account_pubkeys(seed, [tuple(p) for p in targets['paths']]):
            for i, kh, addr in derive_children(pub, chain, int(targets['children'])):
                if kh in khs:
                    hits += 1
                    print(f'*** MATCH: {mn}')
                    print(f'    {label}/0/{i} -> {addr}')
    print(f'checked {len(cands)} candidate(s); {hits} match(es)')
    return 0


# ============================================================ brute force
KNOWN_WORDS = ['visa', 'ivory', 'old', 'captain', 'magnet', 'adapt',
               'produce', 'pumpkin', 'demand', 'demand']


def _search_worker(job):
    """job = (mnemonics, keyhashes, paths, children) -> (mn, path, addr) or None."""
    mnemonics, khs, paths, children = job
    for mn in mnemonics:
        seed = mnemonic_to_seed(mn)
        for purpose, coin, account in paths:
            k, c = account_keys(seed, purpose, coin, account)
            pub = priv_to_pub(k)
            for i, kh, addr in derive_children(pub, c, children):
                if kh in khs:
                    return (mn, f"m/{purpose}'/{coin}'/{account}'/0/{i}", addr)
    return None


def _run_parallel(cands, khs, paths, children, workers, batch=2000):
    from concurrent.futures import ProcessPoolExecutor, wait, FIRST_COMPLETED
    it = iter(cands)
    inflight = set()
    found = None
    ex = ProcessPoolExecutor(max_workers=workers)
    try:
        def refill():
            while len(inflight) < max(2, workers * 2):
                b = []
                try:
                    while len(b) < batch:
                        b.append(next(it))
                except StopIteration:
                    pass
                if not b:
                    return False
                inflight.add(ex.submit(_search_worker, (b, khs, paths, children)))
            return True
        refill()
        while inflight:
            done, _ = wait(inflight, return_when=FIRST_COMPLETED)
            for f in done:
                res = f.result()
                inflight.discard(f)
                if res:
                    found = res
                    break
            if found or (not inflight and not refill()):
                break
    finally:
        for f in list(inflight):
            f.cancel()
        ex.shutdown(wait=False, cancel_futures=True)
    return found


def cmd_brute(args):
    """Checksum-pruned BIP39 seed search, fully offline, checkpointed."""
    wl = ensure_wordlist(args.wordlist)
    targets = load_targets(args.targets)
    khs = set(target_keyhashes(targets))
    paths = [tuple(p) for p in targets['paths']]
    children = int(targets['children'])
    print(f'targets: {targets.get("label")} ({len(khs)} keyhashes) | '
          f'paths={paths} | children 0..{children - 1}')

    if args.literal:
        known = [wl.index(w) for w in KNOWN_WORDS]
        unknown_ix = list(range(2048))
        print('mode=literal: 10 known words, 2 unknown positions')
    else:
        known = [wl.index(w) for w in KNOWN_WORDS[:9]]
        if args.topics:
            words = [w.strip() for w in open(args.topics, encoding='utf-8') if w.strip()]
            unknown_ix = sorted({wl.index(w) for w in words if w in wl})
            print(f'mode=deep | subset alphabet {len(unknown_ix)} words '
                  f'-> ~{len(unknown_ix) ** 3 // 16:,} candidates')
        else:
            unknown_ix = list(range(2048))
            print('mode=deep | full alphabet -> ~536,870,912 candidates')

    cands = gen_candidates(known, unknown_ix, wl, checkpoint=args.checkpoint,
                           limit=args.limit)
    t0 = time.time()
    try:
        found = _run_parallel(cands, khs, paths, children, args.workers)
    except KeyboardInterrupt:
        found = None
        pos = 'unknown'
        if args.checkpoint and os.path.exists(args.checkpoint):
            try:
                st = json.load(open(args.checkpoint, encoding='utf-8'))
                pos = f"i9={st.get('i9')} i10={st.get('i10')} count={st.get('count'):,}"
            except Exception:
                pass
        print(f'\ninterrupted - checkpoint position: {pos}')
        print(f'resume with: --checkpoint {args.checkpoint or "<file>"}')
        return 130
    print(f'search ran {time.time() - t0:.1f}s')
    if found:
        mn, path, addr = found
        print('\n*** MATCH FOUND ***')
        print(f'mnemonic : {mn}')
        print(f'path     : {path}')
        print(f'address  : {addr}')
        with open(args.found_file, 'w', encoding='utf-8', newline='\n') as f:
            json.dump({'mnemonic': mn, 'path': path, 'address': addr,
                       'found': time.strftime('%Y-%m-%dT%H:%M:%S')}, f, indent=1)
        print(f'written to {args.found_file}')
        return 0
    print('no match in the searched space')
    return 0


# ============================================================ scan
def cmd_scan(args):
    """Balance / UTXO lookup for a target list. --offline reads the cache."""
    addrs = []
    if args.addresses:
        addrs += [a.strip() for a in open(args.addresses, encoding='utf-8') if a.strip()]
    if args.targets:
        addrs += load_targets(args.targets).get('addresses', [])
    addrs = sorted(set(addrs))
    if not addrs:
        print('no addresses supplied (use --addresses FILE or --targets FILE)')
        return 2

    if args.offline:
        if not os.path.exists(args.cache):
            print(f'--offline but no cache at {args.cache}')
            return 2
        data = json.load(open(args.cache, encoding='utf-8'))
        print(f'cache: {args.cache} (written {data.get("_ts", "?")})')
        results = data.get('results', data)
    else:
        results = _network_scan(addrs, args.endpoint)

    funded = [(a, r) for a, r in results.items()
              if isinstance(r, dict) and (r.get('received') or r.get('unspent'))]
    print(f'scanned {len(addrs)} address(es); {len(funded)} with history/balance')
    for a, r in funded:
        print(f'  {a}  received={r.get("received", 0):,}  unspent={r.get("unspent", 0):,}  '
              f'txs={r.get("txs", "?")}')
    if not args.offline and args.cache:
        with open(args.cache, 'w', encoding='utf-8', newline='\n') as f:
            json.dump({'_ts': time.strftime('%Y-%m-%dT%H:%M:%S'), 'results': results}, f, indent=1)
        print(f'cache written -> {args.cache}')
    if args.json:
        json.dump(results, open(args.json, 'w', encoding='utf-8', newline='\n'), indent=1)
    return 0


def _network_scan(addrs, endpoint):
    """The ONLY place this file touches the network (opt-in via `scan`)."""
    import urllib.request
    out = {}
    for a in addrs:
        try:
            req = urllib.request.Request(f'{endpoint}/address/{a}',
                                         headers={'User-Agent': 'offline-toolkit/1.0'})
            with urllib.request.urlopen(req, timeout=15) as r:
                d = json.load(r)
            cs, ms = d.get('chain_stats', {}), d.get('mempool_stats', {})
            out[a] = {
                'received': cs.get('funded_txo_sum', 0) + ms.get('funded_txo_sum', 0),
                'unspent': (cs.get('funded_txo_sum', 0) - cs.get('spent_txo_sum', 0)
                            + ms.get('funded_txo_sum', 0) - ms.get('spent_txo_sum', 0)),
                'txs': cs.get('tx_count', 0) + ms.get('tx_count', 0),
            }
        except Exception as e:
            out[a] = {'error': str(e)}
        time.sleep(0.15)
    return out


# ============================================================ psbt audit (offline)
def _read_varint(buf, pos):
    b = buf[pos]
    if b < 0xfd:
        return b, pos + 1
    if b == 0xfd:
        return struct.unpack('<H', buf[pos + 1:pos + 3])[0], pos + 3
    if b == 0xfe:
        return struct.unpack('<I', buf[pos + 1:pos + 5])[0], pos + 5
    return struct.unpack('<Q', buf[pos + 1:pos + 9])[0], pos + 9


def _read_map(raw, pos):
    out = {}
    while True:
        klen, pos = _read_varint(raw, pos)
        if klen == 0:
            return out, pos
        key = raw[pos:pos + klen]
        pos += klen
        vlen, pos = _read_varint(raw, pos)
        out[key] = raw[pos:pos + vlen]
        pos += vlen


def _script_to_address(spk):
    if len(spk) == 22 and spk[:2] == b'\x00\x14':
        return addr_of_keyhash(spk[2:].hex()), 'p2wpkh'
    if len(spk) == 25 and spk[:3] == b'\x76\xa9\x14':
        return _b58check(b'\x00' + spk[3:23]), 'p2pkh'
    if len(spk) == 23 and spk[:2] == b'\xa9\x14':
        return _b58check(b'\x05' + spk[2:22]), 'p2sh'
    if len(spk) == 34 and spk[:2] == b'\x00\x20':
        return bech32_encode('bc', 0, spk[2:]), 'p2wsh'
    if len(spk) == 34 and spk[:2] == b'\x51\x20':
        return bech32_encode('bc', 1, spk[2:]), 'p2tr'
    return None, f'unknown({len(spk)}b)'


def _parse_raw_tx(buf):
    ver = struct.unpack('<I', buf[:4])[0]
    pos = 4
    segwit = False
    if buf[4:6] == b'\x00\x01':
        segwit = True
        pos = 6
    nin, pos = _read_varint(buf, pos)
    ins = []
    for _ in range(nin):
        txid = buf[pos:pos + 32][::-1].hex()
        vout = struct.unpack('<I', buf[pos + 32:pos + 36])[0]
        slen, p2 = _read_varint(buf, pos + 36)
        pos = p2 + slen + 4
        ins.append((txid, vout))
    nout, pos = _read_varint(buf, pos)
    outs = []
    for _ in range(nout):
        amt = struct.unpack('<Q', buf[pos:pos + 8])[0]
        slen, p2 = _read_varint(buf, pos + 8)
        spk = buf[p2:p2 + slen]
        pos = p2 + slen
        outs.append((amt, spk.hex()))
    return {'version': ver, 'segwit': segwit, 'inputs': ins, 'outputs': outs}


def cmd_psbt(args):
    raw = open(args.file, 'rb').read()
    if raw[:5] != b'psbt\xff':
        try:
            raw = base64.b64decode(b''.join(raw.split()))
        except Exception:
            pass
    print(f'file: {args.file} ({len(raw)} bytes)')
    if raw[:5] != b'psbt\xff':
        print('not a PSBT (bad magic)')
        return 2
    print('magic: OK')
    glob, pos = _read_map(raw, 5)
    # PSBT_GLOBAL_UNSIGNED_TX = 0x00 (v0); 0x01 would be PSBT_GLOBAL_XPUB
    if b'\x00' not in glob:
        print('no unsigned tx in global map (key 0x00)')
        if b'\x01' in glob:
            print('note: found key 0x01 => this looks like PSBTv2 or an xpub-only global map')
        return 2
    tx = _parse_raw_tx(glob[b'\x00'])
    print(f'unsigned tx: v{tx["version"]} | inputs {len(tx["inputs"])} | '
          f'outputs {len(tx["outputs"])}')
    for i, (txid, vout) in enumerate(tx['inputs']):
        print(f'  in[{i}] {txid}:{vout}')
    for i, (amt, spk) in enumerate(tx['outputs']):
        addr, kind = _script_to_address(bytes.fromhex(spk))
        print(f'  out[{i}] {amt:,} sats -> {addr} ({kind})')
    in_maps = []
    for i in range(len(tx['inputs'])):
        try:
            m, pos = _read_map(raw, pos)
        except Exception:
            print(f'  (file truncated after input map {i})')
            break
        in_maps.append(m)
    if len(in_maps) < len(tx['inputs']):
        print(f'WARNING: truncated - {len(in_maps)}/{len(tx["inputs"])} input maps present')
    sigs = 0
    for i, m in enumerate(in_maps):
        info = ''
        wu = m.get(b'\x01')
        if wu and len(wu) >= 9:
            amt = struct.unpack('<Q', wu[:8])[0]
            slen, p2 = _read_varint(wu, 8)
            addr, kind = _script_to_address(wu[p2:p2 + slen])
            info = f'{amt:,} sats from {addr} ({kind})'
        psigs = [k for k in m if k[:1] == b'\x02']
        sigs += len(psigs)
        note = ''
        nw = m.get(b'\x00')
        if nw:
            h = sha256d(nw)[::-1].hex()
            exp = tx['inputs'][i][0] if i < len(tx['inputs']) else ''
            note = (f' | non-witness utxo {h[:16]}... '
                    f'{"MATCHES prev" if h == exp else "MISMATCH vs prev txid"}')
        print(f'  in[{i}] {info} | partial sigs: {len(psigs)}{note}')
    print(f'total partial signatures: {sigs}')
    if in_maps and sigs == 0:
        print('=> PSBT is UNSIGNED (cannot be broadcast as-is)')
    return 0


# ============================================================ gpu work pack
GPU_ENV = """# Work pack for github.com/ipsbruno3/bitcoin-mnemonic-recovery (OpenCL, Linux)
# Generated offline by offline_toolkit.py -> copy over the repo's .env
SEED="{seed}"
GPU_THREADS=32000
SAVE_PROGRESS=1
RANDOM=0
ELECTRUM_SEED=0
"""

GPU_RUN = """# GPU Work Pack - partial-seed recovery

Generated offline on {ts}.

## Inputs

- Phrase template (`?` = unknown word): `{template}`
- Unknown positions: {n_unknown} -> checksum-pruned space ~{space:,} candidates
- Targets ({label}): {n_addrs} address(es), see `addresses.txt`
- Derivation verified on a hit: `m/84'/0'/0'/0/0` (BIP84 native SegWit)

## Engine (source-available, auditable)

`github.com/ipsbruno3/bitcoin-mnemonic-recovery` - OpenCL, multi-GPU, checkpointing,
BIP-39 + BIP-84.

THROUGHPUT - stated by the project README only, NOT verified by us:
~1,000,000 seeds/s (RTX 5090) and ~600,000 seeds/s (RTX 5080) in BIP-39 mode.
Treat as a vendor claim: run the repo's own benchmark on your card before planning
around it, and note that wall-clock time also includes PBKDF2 load and address
comparison, not just kernel throughput.

```
git clone https://github.com/ipsbruno3/bitcoin-mnemonic-recovery
cd bitcoin-mnemonic-recovery
python3 -m venv venv && source venv/bin/activate
python -m pip install -U numpy pyopencl python-dotenv mnemonic rich requests bech32
cp {outdir}/.env .
cp {outdir}/addresses.txt .
python3 main.py            # or: main.py 1  to pick GPU index 1
```

Checkpointing: `SAVE_PROGRESS=1` -> `state.json`.
If the kernel build fails: remove `kernel/cache/*.clbin`; check `clinfo | head -n 20`.

## Verify a hit independently (never trust one tool)

```
python3 offline_toolkit.py verify --mnemonic "<recovered phrase>" --targets {targets_arg}
```

Only a phrase that BOTH the GPU tool and this verifier accept controls the targets.

## Other engines

- **Seed Savior** (browser: 3rditeration.github.io/mnemonic-recovery) - same `?` syntax;
  fine for ONE unknown word, impractical for three (runs in a browser tab).
- WARNING: **CUDA_Mnemonic_Recovery (isananny8515)** - avoid. It distributes a prebuilt
  Windows binary from a raw.githubusercontent.com link instead of GitHub Releases, with
  0 stars, 0 forks and no release artifacts. Unverifiable binaries are unacceptable risk
  on a machine that will handle seed material. Prefer auditable source.

## Security

- Run locally on hardware you control; the engine can be used with its Telegram/report
  modules disabled for a fully offline workflow.
- Target addresses are public (no leak), but a recovered phrase is a live key: never paste
  it into a website, chat, or unknown binary.
"""


def cmd_gpu(args):
    """Emit a ready-to-run GPU work pack (offline generation, no network)."""
    targets = load_targets(args.targets)
    addrs = targets.get('addresses', [])
    known = KNOWN_WORDS[:9] if not args.literal else KNOWN_WORDS
    n_unknown = 12 - len(known)
    template = ' '.join(known + ['?'] * n_unknown)
    space = 2048 ** n_unknown // 16
    os.makedirs(args.outdir, exist_ok=True)
    files = {
        '.env': GPU_ENV.format(seed=template),
        'addresses.txt': '\n'.join(addrs) + '\n',
        'phrase_template.txt': template + '\n',
        'RUN.md': GPU_RUN.format(ts=time.strftime('%Y-%m-%d %H:%M:%S'), template=template,
                                 n_unknown=n_unknown, space=space,
                                 label=targets.get('label'), n_addrs=len(addrs),
                                 outdir=args.outdir,
                                 targets_arg=args.targets or 'targets.json'),
    }
    for name, content in files.items():
        p = os.path.join(args.outdir, name)
        with open(p, 'w', encoding='utf-8', newline='\n') as f:
            f.write(content)
        print(f'  wrote {p}')
    print(f'phrase template: {template}')
    print(f'search space   : ~{space:,} candidates ({n_unknown} unknown positions)')
    return 0


# ============================================================ render
def _esc(s):
    return s.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')


def _md_inline(s):
    out = _esc(s)
    while '`' in out:
        out = out.replace('`', '<code>', 1)
        if '`' in out:
            out = out.replace('`', '</code>', 1)
    # **bold** -> <strong> (placeholder survives the <code> pass above)
    while '**' in out:
        out = out.replace('**', '\x00', 1)
        out = out.replace('**', '\x01', 1) if '**' in out else out
    out = out.replace('\x00', '<strong>').replace('\x01', '</strong>')
    return out


def _md_block(lines):
    """Render a markdown block into HTML, grouping list items into <ul>."""
    html, in_ul = [], False
    for line in lines:
        s = line.strip()
        if not s:
            continue
        if s in ('---', '***', '___'):
            if in_ul:
                html.append('</ul>')
                in_ul = False
            html.append('<hr>')
            continue
        if s.startswith('## '):
            if in_ul:
                html.append('</ul>')
                in_ul = False
            html.append(f'<h2>{_md_inline(s[3:])}</h2>')
            continue
        if s.startswith('- '):
            if not in_ul:
                html.append('<ul>')
                in_ul = True
            html.append(f'<li>{_md_inline(s[2:])}</li>')
            continue
        if s.startswith('|'):
            if in_ul:
                html.append('</ul>')
                in_ul = False
            if '---' in s:
                continue
            cells = [c.strip() for c in s.strip('|').split('|')]
            tag = 'th' if cells and cells[0] == 'checkpoint' else 'td'
            html.append('<tr>' + ''.join(
                f'<{tag}>{_md_inline(c)}</{tag}>' for c in cells) + '</tr>')
            continue
        if in_ul:
            html.append('</ul>')
            in_ul = False
        html.append(f'<p>{_md_inline(s)}</p>')
    if in_ul:
        html.append('</ul>')
    return html


def cmd_render(args):
    """Offline report rendering: Markdown + standalone HTML."""
    t = time.strftime('%Y-%m-%d %H:%M:%S')
    targets = [load_targets(p) for p in args.targets] if args.targets else [load_targets(None)]
    ckpts = args.checkpoint or ['deep_checkpoint.json', 'kwikbit_prefilter_checkpoint.json']
    rows, found = [], []
    for c in ckpts:
        if os.path.exists(c):
            try:
                st = json.load(open(c, encoding='utf-8'))
                rows.append((c, st.get('count', 0), st.get('subset', 2048),
                             st.get('i9'), st.get('i10')))
            except Exception:
                pass
    for ff in (args.found_file or ['FOUND.json']):
        if os.path.exists(ff):
            found.append(json.load(open(ff, encoding='utf-8')))
    scan = json.load(open(args.cache, encoding='utf-8')) if (args.cache and os.path.exists(args.cache)) else None

    md = ['# Search Status Report', '', f'Generated: {t}', '', '## Targets', '']
    for tg in targets:
        md.append(f"- **{tg.get('label')}** - {len(tg.get('addresses', []))} address(es), "
                  f"paths {tg['paths']}, children 0..{int(tg['children']) - 1}")
        for a in tg.get('addresses', []):
            md.append(f'  - `{a}`')
    md += ['', '## Search checkpoints', '',
           '| checkpoint | done | space | position |', '|---|---|---|---|']
    for name, count, subset, i9, i10 in rows:
        space = f'{subset ** 3 // 16:,}' if subset < 2048 else '536,870,912'
        md.append(f'| `{name}` | {count:,} | {space} | i9={i9} i10={i10} |')
    md += ['', '## Matches found', '']
    if found:
        for f_ in found:
            md.append(f"- `{f_.get('mnemonic')}` -> {f_.get('path')} -> `{f_.get('address')}`")
    else:
        md.append('None yet.')
    if scan:
        res = scan.get('results', scan)
        funded = {a: r for a, r in res.items()
                  if isinstance(r, dict) and (r.get('received') or r.get('unspent'))}
        md += ['', '## Balance scan', '',
               f'Addresses checked: {len(res)}; with history: {len(funded)}', '']
        for a, r in list(funded.items())[:50]:
            md.append(f"- `{a}` received={r.get('received', 0):,} "
                      f"unspent={r.get('unspent', 0):,}")
    md += ['', '---', '', 'Tool: `offline_toolkit.py` (offline; read-only re: funds).',
           'Not implemented by design: wallet.dat cracking, nonce forensics, '
           'hardware-wallet sweeping, transaction signing/broadcast.', '']
    with open(args.out_md, 'w', encoding='utf-8', newline='\n') as f:
        f.write('\n'.join(md))
    html = ['<!doctype html><meta charset="utf-8"><title>Search Status Report</title>',
            '<style>body{font:14px/1.6 -apple-system,Segoe UI,Roboto,sans-serif;max-width:900px;'
            'margin:40px auto;padding:0 20px;color:#1a1a1a}h1{border-bottom:2px solid #eee;'
            'padding-bottom:8px}h2{margin-top:32px}code{background:#f4f4f4;padding:2px 5px;'
            'border-radius:3px}table{border-collapse:collapse;width:100%;margin:12px 0}'
            'td,th{border:1px solid #e2e2e2;padding:6px 10px;text-align:left;font-size:13px}'
            'th{background:#fafafa}hr{border:0;border-top:1px solid #eee;margin:28px 0}'
            'p.note{color:#666;font-size:12px}</style>',
            '<h1>Search Status Report</h1>', f'<p>Generated: {t}</p>']
    body = _md_block(md[3:])
    # wrap consecutive table rows in a <table>
    out, open_tbl = [], False
    for el in body:
        if el.startswith('<tr>'):
            if not open_tbl:
                out.append('<table>')
                open_tbl = True
            out.append(el)
        else:
            if open_tbl:
                out.append('</table>')
                open_tbl = False
            out.append(el)
    if open_tbl:
        out.append('</table>')
    html.extend(out)
    with open(args.out_html, 'w', encoding='utf-8', newline='\n') as f:
        f.write('\n'.join(html))
    print(f'wrote {args.out_md} and {args.out_html}')
    return 0


# ============================================================ CLI
def _setup_console():
    """Cross-platform console setup: prefer UTF-8, never crash on encoding."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding='utf-8', errors='replace')  # py3.7+
        except Exception:
            pass


def main():
    _setup_console()
    if hasattr(multiprocessing, 'freeze_support'):
        multiprocessing.freeze_support()   # Windows/PyInstaller spawn safety
    ap = argparse.ArgumentParser(
        prog='offline_toolkit.py',
        description='Offline Bitcoin address / balance / seed-search toolkit '
                    '(read-only with respect to funds)')
    sub = ap.add_subparsers(dest='cmd', required=True)

    s = sub.add_parser('selftest', help='validate crypto core offline')
    s.add_argument('--wordlist', default='english.txt')
    s.set_defaults(func=cmd_selftest)

    s = sub.add_parser('gendata', help='auto-generate synthetic dataset')
    s.add_argument('--count', type=int, default=5)
    s.add_argument('--children', type=int, default=5)
    s.add_argument('--out', default='synthetic_dataset.json')
    s.add_argument('--wordlist', default='english.txt')
    s.set_defaults(func=cmd_gendata)

    s = sub.add_parser('derive', help='derive addresses (offline)')
    s.add_argument('--mnemonic')
    s.add_argument('--passphrase')
    s.add_argument('--zpub')
    s.add_argument('--xpub')
    s.add_argument('--paths', default='84/0/0')
    s.add_argument('--children', type=int, default=5)
    s.add_argument('--limit', type=int, default=0)
    s.add_argument('--json')
    s.add_argument('--wordlist', default='english.txt')
    s.set_defaults(func=cmd_derive)

    s = sub.add_parser('verify', help='check candidate mnemonic(s) vs targets (offline)')
    s.add_argument('--mnemonic')
    s.add_argument('--file')
    s.add_argument('--targets')
    s.add_argument('--passphrase')
    s.set_defaults(func=cmd_verify)

    s = sub.add_parser('brute', help='checksum-pruned BIP39 search (offline)')
    s.add_argument('--targets')
    s.add_argument('--topics', help='reduced BIP39 wordlist for unknown positions')
    s.add_argument('--literal', action='store_true')
    s.add_argument('--checkpoint')
    s.add_argument('--limit', type=int, default=0)
    s.add_argument('--workers', type=int, default=max(1, os.cpu_count() or 2))
    s.add_argument('--found-file', dest='found_file', default='FOUND.json')
    s.add_argument('--wordlist', default='english.txt')
    s.set_defaults(func=cmd_brute)

    s = sub.add_parser('scan', help='balance lookup (network; --offline = cache)')
    s.add_argument('--addresses')
    s.add_argument('--targets')
    s.add_argument('--endpoint', default='https://blockstream.info/api')
    s.add_argument('--offline', action='store_true')
    s.add_argument('--cache', default='scan_cache.json')
    s.add_argument('--json')
    s.set_defaults(func=cmd_scan)

    s = sub.add_parser('psbt', help='decode + audit a PSBT file (offline)')
    s.add_argument('file')
    s.set_defaults(func=cmd_psbt)

    s = sub.add_parser('gpu', help='emit a ready-to-run GPU work pack (offline)')
    s.add_argument('--targets')
    s.add_argument('--literal', action='store_true',
                   help='template with 10 known words (2 unknown) instead of 9 (3 unknown)')
    s.add_argument('--outdir', default='gpu_pack')
    s.set_defaults(func=cmd_gpu)

    s = sub.add_parser('render', help='write MD + HTML status report (offline)')
    s.add_argument('--targets', action='append')
    s.add_argument('--checkpoint', action='append')
    s.add_argument('--found-file', dest='found_file', action='append')
    s.add_argument('--cache')
    s.add_argument('--out-md', dest='out_md', default='status_report.md')
    s.add_argument('--out-html', dest='out_html', default='status_report.html')
    s.set_defaults(func=cmd_render)

    args = ap.parse_args()
    return args.func(args)


if __name__ == '__main__':
    sys.exit(main())
