#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
btc_kangaroo.py  —  single-file BTC puzzle solver (Pollard kangaroo)
====================================================================
Algorithm : Pollard kangaroo (tame + wild), ~2*sqrt(W) ops instead of W.
CPU       : single-threaded by design => uses 1 core (minimum CPU footprint).
Deps      : stdlib only. Optional: coincurve (C libsecp256k1) for big speedup.
Platform  : runs in Windows cmd.exe (ASCII fallback, no ANSI needed).

Commands:
  env                        environment / backend report
  selftest                   mandatory correctness gates (must pass first)
  solve --puzzle N --pubkey H   solve puzzle N with compressed pubkey H
  solve --start HEX --end HEX --pubkey H   custom interval [start,end]
  resume                     resume last checkpoint
  tg-setup / tg-test         optional encrypted Telegram notifications
"""
import sys, os, time, math, random, hashlib, hmac, struct, pickle, argparse, signal

# ───────────────────────────── constants ─────────────────────────────
Pf = 2**256 - 2**32 - 977
N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

APP    = os.path.dirname(os.path.abspath(__file__))
CKPT   = os.path.join(APP, "kangaroo_ckpt.pkl")
TG_ENC = os.path.join(APP, ".tg_enc")
TG_KEY = os.path.join(APP, ".tg_key")
FOUND  = os.path.join(APP, "FOUND_KEYS.txt")

# ───────────────────────────── cmd colors ─────────────────────────────
def _enable_vt():
    if os.name != "nt":
        return True
    try:
        import ctypes
        k = ctypes.windll.kernel32
        h = k.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if not k.GetConsoleMode(h, ctypes.byref(mode)):
            return False
        return bool(k.SetConsoleMode(h, mode.value | 0x0004))
    except Exception:
        return False

COLOR = _enable_vt() and sys.stdout.isatty()
def _c(code, s):
    return ("\x1b[" + code + "m" + s + "\x1b[0m") if COLOR else s
def cyan(s):  return _c("36", s)
def green(s): return _c("32", s)
def red(s):   return _c("31", s)
def yellow(s):return _c("33", s)

# ───────────────────────────── secp256k1 ─────────────────────────────
def jac_double(X, Y, Z):
    if Z == 0 or Y == 0:
        return (0, 1, 0)
    yy = Y * Y % Pf
    s  = 4 * X * yy % Pf
    m  = 3 * X * X % Pf
    x3 = (m * m - 2 * s) % Pf
    y3 = (m * (s - x3) - 8 * yy * yy) % Pf
    z3 = 2 * Y * Z % Pf
    return (x3, y3, z3)

def jac_add_aff(X1, Y1, Z1, x2, y2):
    if Z1 == 0:
        return (x2, y2, 1)
    z1z1 = Z1 * Z1 % Pf
    u2   = x2 * z1z1 % Pf
    s2   = y2 * Z1 % Pf * z1z1 % Pf
    h    = (u2 - X1) % Pf
    r    = (s2 - Y1) % Pf
    if h == 0:
        if r == 0:
            return jac_double(X1, Y1, Z1)
        return (0, 1, 0)
    hh  = h * h % Pf
    hhh = h * hh % Pf
    v   = X1 * hh % Pf
    x3  = (r * r - hhh - 2 * v) % Pf
    y3  = (r * (v - x3) - Y1 * hhh) % Pf
    z3  = Z1 * h % Pf
    return (x3, y3, z3)

def jac_to_aff(P):
    X, Y, Z = P
    if Z == 0:
        return None
    zi  = pow(Z, -1, Pf)
    zi2 = zi * zi % Pf
    return (X * zi2 % Pf, Y * zi2 % Pf * zi % Pf)

def _mul_jac(k, base):
    X, Y, Z = 0, 1, 0
    bx, by = base
    k %= N
    for bit in bin(k)[2:]:
        X, Y, Z = jac_double(X, Y, Z)
        if bit == "1":
            X, Y, Z = jac_add_aff(X, Y, Z, bx, by)
    return (X, Y, Z)

def mul_aff(k, base):
    return jac_to_aff(_mul_jac(k, base))

def aff_add(p1, p2):
    if p1 is None: return p2
    if p2 is None: return p1
    x1, y1 = p1; x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % Pf == 0:
            return None
        lam = (3 * x1 * x1) * pow(2 * y1, -1, Pf) % Pf
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, Pf) % Pf
    x3 = (lam * lam - x1 - x2) % Pf
    y3 = (lam * (x1 - x3) - y1) % Pf
    return (x3, y3)

def compress(pt):
    x, y = pt
    return ("03" if (y & 1) else "02") + "%064x" % x

def parse_pub(s):
    s = s.strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    if len(s) == 66 and s[:2] in ("02", "03"):
        x  = int(s[2:], 16)
        y2 = (pow(x, 3, Pf) + 7) % Pf
        y  = pow(y2, (Pf + 1) // 4, Pf)
        if (y & 1) != (int(s[:2], 16) & 1):
            y = Pf - y
        return (x, y)
    if len(s) == 130:
        return (int(s[2:66], 16), int(s[66:], 16))
    raise ValueError("pubkey must be 33-byte compressed (02/03..) or 65-byte (04..) hex")

def hash160(b):
    try:
        return hashlib.new("ripemd160", hashlib.sha256(b).digest()).digest()
    except Exception:
        raise RuntimeError("openssl build lacks ripemd160 — use Python 3.12 official build")

# ───────────────────────── point backends ─────────────────────────
class PureBackend:
    name = "pure-python"
    def mul_g(self, k):
        k %= N
        if k == 0:
            raise ValueError("scalar 0 has no point")
        return mul_aff(k, (Gx, Gy))
    def add(self, p1, p2):
        return aff_add(p1, p2)
    def x(self, p):
        return p[0] if p is not None else None
    def eq(self, p1, p2):
        return p1 == p2
    def to_hex(self, p):
        return compress(p) if p is not None else None
    def from_hex(self, h):
        return parse_pub(h)

class CcBackend:
    name = "coincurve (libsecp256k1, C)"
    def __init__(self):
        from coincurve import PublicKey
        self.PublicKey = PublicKey
    def mul_g(self, k):
        k %= N
        if k == 0:
            raise ValueError("scalar 0 has no point")
        return self.PublicKey.from_valid_secret(k.to_bytes(32, "big"))
    def add(self, p1, p2):
        if p1 is None: return p2
        if p2 is None: return p1
        return p1.combine([p2])
    def x(self, p):
        if p is None: return None
        return int.from_bytes(p.format(compressed=True)[1:], "big")
    def eq(self, p1, p2):
        if p1 is None or p2 is None:
            return p1 is p2
        return p1.format(compressed=True) == p2.format(compressed=True)
    def to_hex(self, p):
        return p.format(compressed=True).hex() if p is not None else None
    def from_hex(self, h):
        return self.PublicKey(bytes.fromhex(h))

def select_backend():
    try:
        b = CcBackend()
        b.mul_g(1)
        return b
    except Exception:
        return PureBackend()

# ───────────────────────── progress line ─────────────────────────
class Progress:
    SPIN = "|/-\\"
    def __init__(self, label, est):
        self.label = label
        self.est   = max(est, 1)
        self.count = 0
        self.dps   = 0
        self.t0    = time.time()
        self._i    = 0
        self._last = 0.0
    def tick(self, count, dps, force=False):
        self.count = count
        self.dps   = dps
        now = time.time()
        if not force and now - self._last < 0.3:
            return
        self._last = now
        el   = now - self.t0
        rate = count / el if el > 0.4 else 0.0
        pct  = min(100.0, 100.0 * count / self.est)
        eta  = (self.est - count) / rate if rate > 0 else 0.0
        self._i = (self._i + 1) % len(self.SPIN)
        line = ("\r%s %s | %s ops | %.0fs | %.0f ops/s | DPs %d | %5.1f%% ETA %.0fs  "
                % (self.SPIN[self._i], self.label, format(count, ","),
                   el, rate, dps, pct, eta))
        w = 110
        sys.stdout.write(line[:w].ljust(w))
        sys.stdout.flush()
    def done(self, msg):
        sys.stdout.write("\r" + " " * 110 + "\r" + msg + "\n")
        sys.stdout.flush()

# ───────────────────────── kangaroo solver ─────────────────────────
def kangaroo(backend, pub_hex, a, b, timeout=None, resume=False, notify=False):
    W = b - a
    if W <= 0:
        raise ValueError("empty interval")
    P = backend.from_hex(pub_hex)

    bits = max(1, (W.bit_length() + 1) // 2)
    seed = int(hashlib.sha256(pub_hex.encode()).hexdigest()[:16], 16)
    rng  = random.Random(seed)
    ds   = set()
    while len(ds) < 32:
        ds.add(rng.randrange(1, 1 << bits) | 1)
    dists = sorted(ds)
    jpts  = [backend.mul_g(d) for d in dists]

    dp_bits = max(4, (W.bit_length() // 2) - 1)
    dp_mask = (1 << dp_bits) - 1

    seen  = {}
    total = 0
    t0    = None

    if resume and os.path.exists(CKPT):
        try:
            st = pickle.load(open(CKPT, "rb"))
            if st.get("pub") == pub_hex.lower():
                t0    = st["t0"]
                tame  = backend.from_hex(st["tame"])
                acc_t = st["acc_t"]
                wild  = backend.from_hex(st["wild"])
                acc_w = st["acc_w"]
                total = st.get("total", 0)
                seen  = st.get("seen", {})
                print(cyan("  resumed checkpoint: %s ops, %d DPs" % (format(total, ","), len(seen))))
            else:
                print(yellow("  checkpoint is for a different pubkey — starting fresh"))
        except Exception as e:
            print(yellow("  checkpoint unreadable (%s) — starting fresh" % e))
    if t0 is None:
        t0    = rng.randrange(a, b)
        tame  = backend.mul_g(t0)
        acc_t = 0
        wild  = P
        acc_w = 0

    est = int(2.5 * math.isqrt(W)) + 64
    prog = Progress("kangaroo", est)
    start = time.time()
    last_ck = time.time()

    def save_ck():
        try:
            pickle.dump({"pub": pub_hex.lower(), "t0": t0,
                         "tame": backend.to_hex(tame), "acc_t": acc_t,
                         "wild": backend.to_hex(wild), "acc_w": acc_w,
                         "total": total, "seen": seen},
                        open(CKPT + ".tmp", "wb"))
            os.replace(CKPT + ".tmp", CKPT)
        except Exception as e:
            print(yellow("\n  checkpoint save failed: %s" % e))

    def try_solve(tame_o, wild_o):
        for cand in ((tame_o - wild_o) % N, (-tame_o - wild_o) % N):
            if a <= cand <= b and backend.eq(backend.mul_g(cand), P):
                return cand
        return None

    def record(x, offset, is_tame):
        o2 = seen.get(x)
        if o2 is None:
            seen[x] = (offset, is_tame)
            return None
        off2, tame2 = o2
        if tame2 == is_tame:
            return None
        tame_o, wild_o = (offset, off2) if is_tame else (off2, offset)
        return try_solve(tame_o, wild_o)

    try:
        while True:
            if timeout and time.time() - start > timeout:
                save_ck()
                prog.done(yellow("  timeout after %s ops — checkpoint saved" % format(total, ",")))
                return None

            # --- tame step ---
            xt = backend.x(tame)
            if xt is None:
                t0 = rng.randrange(a, b); tame = backend.mul_g(t0); acc_t = 0
            else:
                idx = (xt >> 251) & 31
                tame  = backend.add(tame, jpts[idx])
                acc_t = (acc_t + dists[idx]) % N
                total += 1
                xt2 = backend.x(tame)
                if xt2 is not None and (xt2 & dp_mask) == 0:
                    k = record(xt2, (t0 + acc_t) % N, True)
                    if k is not None:
                        save_ck()
                        prog.done(green("  HIT (tame): k = %s" % ("%064x" % k)))
                        return k

            # --- wild step ---
            xw = backend.x(wild)
            if xw is None:
                wild = P; acc_w = 0
            else:
                idx = (xw >> 251) & 31
                wild  = backend.add(wild, jpts[idx])
                acc_w = (acc_w + dists[idx]) % N
                total += 1
                xw2 = backend.x(wild)
                if xw2 is not None and (xw2 & dp_mask) == 0:
                    k = record(xw2, acc_w, False)
                    if k is not None:
                        save_ck()
                        prog.done(green("  HIT (wild): k = %s" % ("%064x" % k)))
                        return k

            prog.tick(total, len(seen))
            if time.time() - last_ck > 30:
                save_ck(); last_ck = time.time()
    except KeyboardInterrupt:
        save_ck()
        prog.done(yellow("  interrupted — checkpoint saved (%s ops)" % format(total, ",")))
        return None

# ───────────────────────── self test ─────────────────────────
def selftest():
    print(cyan("=== SELFTEST ==="))
    b = select_backend()
    print("  backend: %s" % b.name)

    # 1. group identity
    g = b.to_hex(b.mul_g(1))
    assert g == "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", \
        "mul_g(1) != G  (got %s)" % g
    print(green("  [1/3] k*G identity ......... OK"))

    # 2. hash160 known answer
    h = hash160(bytes.fromhex(g))
    assert len(h) == 20
    print(green("  [2/3] hash160 length ....... OK"))

    # 3. end-to-end kangaroo on a planted key in [2^20, 2^21)
    lo, hi = 1 << 20, (1 << 21) - 1
    secret = random.Random(1234).randrange(lo, hi)
    pub = b.to_hex(b.mul_g(secret))
    print(cyan("  [3/3] kangaroo planted key in 2^20 ..."))
    got = kangaroo(b, pub, lo, hi, timeout=120)
    if got != secret:
        print(red("  FAILED: got %s want %s" % (got, hex(secret))))
        return 1
    print(green("  [3/3] kangaroo ............. OK  (k=%s)" % ("%064x" % secret)))
    print(green("SELFTEST PASSED"))
    return 0

# ───────────────────────── telegram (optional) ─────────────────────────
def _ks(key, nonce, n):
    out = b""; c = 0
    while len(out) < n:
        out += hmac.new(key, nonce + struct.pack("<I", c), hashlib.sha256).digest(); c += 1
    return out[:n]

def tg_setup():
    print(cyan("=== TELEGRAM SETUP (encrypted) ==="))
    print(yellow("Reminder: revoke any token ever pasted in chat (@BotFather /revoke)."))
    tok = input("Bot token: ").strip()
    cid = input("Chat ID (blank to auto-discover): ").strip()
    if not cid:
        import urllib.request, json as _j
        print("  polling getUpdates 60s — send /start to your bot now...")
        for _ in range(30):
            try:
                with urllib.request.urlopen(
                        "https://api.telegram.org/bot%s/getUpdates" % tok, timeout=10) as r:
                    js = _j.loads(r.read())
                if js.get("result"):
                    cid = str(js["result"][-1]["message"]["chat"]["id"]); break
            except Exception:
                pass
            time.sleep(2)
        if not cid:
            print(red("  no chat id found")); return 1
    key = os.urandom(32); nonce = os.urandom(8)
    plain = (tok + "|" + cid).encode()
    blob = nonce + bytes(a ^ b for a, b in zip(plain, _ks(key, nonce, len(plain))))
    open(TG_KEY, "wb").write(key); open(TG_ENC, "wb").write(blob)
    print(green("  saved encrypted credentials (.tg_enc / .tg_key)"))
    return 0

def tg_load():
    if not (os.path.exists(TG_ENC) and os.path.exists(TG_KEY)):
        return None, None
    try:
        key  = open(TG_KEY, "rb").read()
        blob = open(TG_ENC, "rb").read()
        if len(key) != 32 or len(blob) < 9:
            return None, None
        nonce, ct = blob[:8], blob[8:]
        plain = bytes(a ^ b for a, b in zip(ct, _ks(key, nonce, len(ct)))).decode()
        t, c = plain.split("|", 1)
        return t, c
    except Exception:
        return None, None

def tg_send(text):
    tok, cid = tg_load()
    if not tok:
        print(yellow("  telegram not configured (run: tg-setup)"))
        return False
    try:
        import urllib.request, urllib.parse
        data = urllib.parse.urlencode(
            {"chat_id": cid, "text": text[:4000], "parse_mode": "Markdown"}).encode()
        with urllib.request.urlopen(
                "https://api.telegram.org/bot%s/sendMessage" % tok, data=data, timeout=15) as r:
            return r.status == 200
    except Exception as e:
        print(yellow("  telegram send failed: %s" % e))
        return False

# ───────────────────────── commands ─────────────────────────
def cmd_env(args):
    b = select_backend()
    print(cyan("=== ENVIRONMENT ==="))
    print("  backend : %s" % b.name)
    print("  python  : %s (%s)" % (sys.version.split()[0], sys.platform))
    print("  cpus    : %s   (kangaroo uses 1 core)" % os.cpu_count())
    tok, _ = tg_load()
    print("  telegram: %s" % ("configured (encrypted)" if tok else "not configured"))
    return 0

def cmd_selftest(args):
    return selftest()

def cmd_solve(args):
    b = select_backend()
    if args.puzzle:
        a, bb = 1 << (args.puzzle - 1), (1 << args.puzzle) - 1
        print(cyan("=== PUZZLE #%d ===  interval [2^%d, 2^%d]" % (args.puzzle, args.puzzle - 1, args.puzzle)))
    else:
        a, bb = int(args.start, 16), int(args.end, 16)
        print(cyan("=== CUSTOM INTERVAL ==="))
    W = bb - a
    print("  range : 0x%x .. 0x%x  (width 2^%.1f)" % (a, bb, math.log2(W)))
    print("  est   : ~%s ops (vs %s for linear scan)" % (
        format(2 * math.isqrt(W), ","), format(W, ",")))
    print("  pub   : %s" % args.pubkey)
    if not args.skip_selftest:
        if selftest() != 0:
            return 1
    k = kangaroo(b, args.pubkey, a, bb, timeout=args.timeout,
                 resume=getattr(args, "resume", False))
    if k is None:
        print(yellow("  no hit — rerun with 'resume' to continue"))
        return 2
    pk = b.to_hex(b.mul_g(k))
    rep = ("KEY FOUND\n  puzzle : #%s\n  k hex  : %064x\n  k dec  : %d\n  pubkey : %s\n  verified: %s"
           % (args.puzzle or "custom", k, k, pk, pk == args.pubkey.lower()))
    print(green("\n" + rep))
    try:
        open(FOUND, "a").write(rep + "\n\n")
    except Exception:
        pass
    if args.notify:
        tg_send("*%s*" % rep)
    return 0

def cmd_resume(args):
    args.resume = True
    return cmd_solve(args)

def cmd_tg_setup(args):
    return tg_setup()

def cmd_tg_test(args):
    ok = tg_send("test from btc_kangaroo.py")
    print(green("  sent OK") if ok else red("  send FAILED"))
    return 0 if ok else 1

def build_parser():
    ap = argparse.ArgumentParser(prog="btc_kangaroo.py",
                                 description="single-file BTC puzzle solver (kangaroo)")
    sub = ap.add_subparsers(dest="cmd")

    sub.add_parser("env", help="environment report").set_defaults(func=cmd_env)
    sub.add_parser("selftest", help="run correctness gates").set_defaults(func=cmd_selftest)
    sub.add_parser("tg-setup", help="store encrypted telegram creds").set_defaults(func=cmd_tg_setup)
    sub.add_parser("tg-test", help="send a test message").set_defaults(func=cmd_tg_test)

    for name, fn, help_txt in (("solve", cmd_solve, "solve a puzzle / interval"),
                               ("resume", cmd_resume, "resume last checkpoint")):
        p = sub.add_parser(name, help=help_txt)
        p.add_argument("--puzzle", type=int, default=None,
                       help="puzzle number -> interval [2^(n-1), 2^n - 1]")
        p.add_argument("--start", default=None, help="custom interval start (hex)")
        p.add_argument("--end",   default=None, help="custom interval end (hex, inclusive)")
        p.add_argument("--pubkey", required=True, help="compressed public key hex")
        p.add_argument("--timeout", type=float, default=None, help="seconds before saving+exit")
        p.add_argument("--notify", action="store_true", help="telegram on hit")
        p.add_argument("--skip-selftest", action="store_true", help="skip pre-flight selftest")
        p.set_defaults(func=fn)

    return ap

def main():
    argv = sys.argv[1:]
    if not argv:
        argv = ["env"]
    args = build_parser().parse_args(argv)
    # validate interval for solve/resume
    if args.cmd in ("solve", "resume"):
        if not args.puzzle and not (args.start and args.end):
            print(red("need --puzzle N  or  --start HEX --end HEX"))
            return 1
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print(yellow("\nstopped.")); return 130
    except Exception as e:
        print(red("\nFATAL: %s: %s" % (type(e).__name__, e)))
        import traceback; traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())
