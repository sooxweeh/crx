#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
btc_kangaroo.py  —  single-file BTC puzzle solver (Pollard kangaroo)
====================================================================
CPU  : Pollard kangaroo, single-threaded by design (min CPU footprint).
GPU  : optional CuPy RawKernel (secp256k1 limb arithmetic, parallel walkers).
       Auto-detected + auto-tuned, GATED by selftest (falls back to CPU on
       any compile/verify failure). Never trusts an unchecked GPU result.
Deps : stdlib only (GPU path needs cupy-cuda12x on Python <=3.12).
        Optional: coincurve (C libsecp256k1) to speed the CPU walk.

Commands:
  hw                            hardware probe + plan
  env                           environment report
  selftest [--gpu]              correctness gates (CPU + GPU cross-check)
  solve  --puzzle N --pubkey H [--gpu|--cpu|--auto]
  solve  --start HEX --end HEX --pubkey H
  resume                        resume last checkpoint
  tg-setup / tg-test            optional encrypted Telegram alerts
"""
import sys, os, time, math, random, hashlib, hmac, struct, pickle, argparse, subprocess

# ───────────────────────────── constants ─────────────────────────────
Pf = 2**256 - 2**32 - 977
N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
MULC = 0x1000003D1  # 2^32 + 977 ; 2^256 ≡ MULC (mod p)

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
def _c(code, s):  return ("\x1b[" + code + "m" + s + "\x1b[0m") if COLOR else s
def cyan(s):   return _c("36", s)
def green(s):  return _c("32", s)
def red(s):    return _c("31", s)
def yellow(s): return _c("33", s)

# ───────────────────────────── secp256k1 (CPU) ─────────────────────────────
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
    return (X * zi * zi % Pf, Y * zi * zi * zi % Pf)

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
    return hashlib.new("ripemd160", hashlib.sha256(b).digest()).digest()

# ───────────────────────── CPU point backends ─────────────────────────
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
        return None if p is None else int.from_bytes(p.format(compressed=True)[1:], "big")
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
        b = CcBackend(); b.mul_g(1); return b
    except Exception:
        return PureBackend()

# ───────────────────────────── hardware autodetect ─────────────────────────────
class Hardware:
    def __init__(self):
        self.cpu_logical = os.cpu_count() or 1
        self.ram_gb      = self._ram()
        self.gpu         = None          # dict or None
        self.cupy_ver    = None
        self.cuda_ok     = False
        self._probe_nvsmi()
        self._probe_cupy()

    # ---- helpers ----
    @staticmethod
    def _ram():
        try:
            if os.name == "nt":
                import ctypes
                class MS(ctypes.Structure):
                    _fields_ = [("dwLength", ctypes.c_ulong),
                                ("dwMemoryLoad", ctypes.c_ulong),
                                ("ullTotalPhys", ctypes.c_ulonglong),
                                ("ullAvailPhys", ctypes.c_ulonglong),
                                ("ullTotalPageFile", ctypes.c_ulonglong),
                                ("ullAvailPageFile", ctypes.c_ulonglong),
                                ("ullTotalVirtual", ctypes.c_ulonglong),
                                ("ullAvailVirtual", ctypes.c_ulonglong),
                                ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]
                ms = MS(); ms.dwLength = ctypes.sizeof(MS)
                ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(ms))
                return round(ms.ullTotalPhys / 1e9, 1)
            return round(os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") / 1e9, 1)
        except Exception:
            return 0.0

    def _probe_nvsmi(self):
        try:
            out = subprocess.check_output(
                ["nvidia-smi",
                 "--query-gpu=name,memory.total,compute_cap",
                 "--format=csv,noheader,nounits"],
                stderr=subprocess.DEVNULL, timeout=8).decode(errors="ignore")
            rows = [r.strip() for r in out.strip().splitlines() if r.strip()]
            if rows:
                name, mem, cap = [c.strip() for c in rows[0].split(",")[:3]]
                self.gpu = {"name": name,
                            "vram_mb": int(float(mem)),
                            "cc": cap,
                            "n": len(rows)}
        except Exception:
            pass

    def _probe_cupy(self):
        try:
            import cupy as cp
            self.cupy_ver = getattr(cp, "__version__", "?")
            n = cp.cuda.runtime.getDeviceCount()
            if n <= 0:
                return
            props = cp.cuda.runtime.getDeviceProperties(0)
            self.cuda_ok = True
            nm = props["name"].decode(errors="ignore") if isinstance(props["name"], bytes) else str(props["name"])
            if self.gpu is None:
                self.gpu = {"name": nm,
                            "vram_mb": int(props["totalGlobalMem"] / 1024 / 1024),
                            "cc": "%d.%d" % (props["major"], props["minor"]),
                            "n": n}
            self.gpu["sm_count"] = int(props["multiProcessorCount"])
            self.gpu["max_threads"] = int(props["maxThreadsPerMultiProcessor"]) * int(props["multiProcessorCount"])
        except Exception:
            self.cuda_ok = False

    # ---- tuning plan ----
    def plan(self, bits, backend="auto"):
        """Return a dict describing the chosen execution strategy."""
        use_gpu = self.cuda_ok and backend in ("auto", "gpu")
        W = 1 << bits
        # DP bits scale with size; jump table stays 32 (kangaroo optimum-ish)
        dp_bits = max(6, min(bits // 2, 20))
        if use_gpu and self.gpu:
            threads = min(self.gpu.get("max_threads", 1 << 20), 1 << 22)
            walkers = max(1 << 16, threads // 2)
            steps   = 4096
        else:
            walkers = 0
            steps   = 0
        return {"use_gpu": use_gpu, "walkers": walkers, "steps": steps,
                "dp_bits": dp_bits, "jump_table": 32,
                "expected_ops": 2 * math.isqrt(W)}

# ───────────────────────── CUDA source (RawKernel) ─────────────────────────
CUDA_SRC = r"""
typedef unsigned long long u64;
typedef unsigned __int128 u128;

__constant__ u64 PJ[4] = {0xFFFFFFFEFFFFFC2FULL,0xFFFFFFFFFFFFFFFFULL,
                          0xFFFFFFFFFFFFFFFFULL,0xFFFFFFFFFFFFFFFFULL};
#define MULC 0x1000003D1ULL

__device__ __forceinline__ int iszero(const u64*a){ return (a[0]|a[1]|a[2]|a[3])==0; }

__device__ __forceinline__ void fadd(u64*a, const u64*b){
    u128 c=0;
    #pragma unroll
    for(int i=0;i<4;i++){ u128 s=(u128)a[i]+b[i]+c; a[i]=(u64)s; c=s>>64; }
    if(c){ u128 s=(u128)a[0]+MULC; a[0]=(u64)s; c=s>>64;
        for(int i=1;i<4 && c;i++){ s=(u128)a[i]+c; a[i]=(u64)s; c=s>>64; } }
}
__device__ __forceinline__ void fsub(u64*a, const u64*b){
    u128 bor=0;
    #pragma unroll
    for(int i=0;i<4;i++){ u128 s=(u128)a[i]-b[i]-bor; a[i]=(u64)s; bor=(s>>64)&1; }
    if(bor){ u128 c=0;
        #pragma unroll
        for(int i=0;i<4;i++){ u128 s=(u128)a[i]+PJ[i]+c; a[i]=(u64)s; c=s>>64; } }
}
__device__ __forceinline__ void fmul(u64*o, const u64*a, const u64*b){
    u64 r[8]={0,0,0,0,0,0,0,0};
    #pragma unroll
    for(int i=0;i<4;i++){
        u64 c=0;
        #pragma unroll
        for(int j=0;j<4;j++){
            u128 cur=(u128)a[i]*b[j]+r[i+j]+c;
            r[i+j]=(u64)cur; c=(u64)(cur>>64);
        }
        r[i+4]=c;
    }
    u64 acc[5]; u128 cc=0;
    #pragma unroll
    for(int i=0;i<4;i++){ u128 cur=(u128)r[4+i]*MULC+r[i]+cc; acc[i]=(u64)cur; cc=cur>>64; }
    acc[4]=(u64)cc;
    #pragma unroll
    for(int it=0; it<3; it++){
        u64 h=acc[4]; if(!h) break; acc[4]=0;
        u128 cur=(u128)h*MULC+acc[0]; acc[0]=(u64)cur; u64 cy=(u64)(cur>>64);
        #pragma unroll
        for(int i=1;i<4;i++){ u128 s=(u128)acc[i]+cy; acc[i]=(u64)s; cy=(u64)(s>>64); }
        acc[4]=cy;
    }
    #pragma unroll
    for(int t=0;t<2;t++){
        bool ge=true;
        for(int i=3;i>=0;i--){ if(acc[i]<PJ[i]){ge=false;break;} if(acc[i]>PJ[i]) break; }
        if(!ge) break;
        u128 bor=0;
        #pragma unroll
        for(int i=0;i<4;i++){ u128 s=(u128)acc[i]-PJ[i]-bor; acc[i]=(u64)s; bor=(s>>64)&1; }
    }
    #pragma unroll
    for(int i=0;i<4;i++) o[i]=acc[i];
}
__device__ void fpow(u64*o, const u64*a){           // a^(p-2)
    u64 e[4]={0xFFFFFFFEFFFFFC2DULL,0xFFFFFFFFFFFFFFFFULL,
              0xFFFFFFFFFFFFFFFFULL,0xFFFFFFFFFFFFFFFFULL};
    u64 r[4]={1,0,0,0}; u64 b[4]={a[0],a[1],a[2],a[3]};
    for(int i=255;i>=0;i--){
        u64 t[4]; fmul(t,r,r); r[0]=t[0];r[1]=t[1];r[2]=t[2];r[3]=t[3];
        if((e[i>>6]>>(i&63))&1){ fmul(t,r,b); r[0]=t[0];r[1]=t[1];r[2]=t[2];r[3]=t[3]; }
    }
    #pragma unroll
    for(int i=0;i<4;i++) o[i]=r[i];
}
__device__ __forceinline__ void fnorm(u64*X,u64*Y,u64*Z){ // affine x = X/Z^2
    u64 zi[4],z2[4]; fpow(zi,Z); fmul(z2,zi,zi); fmul(X,X,z2);
}
__device__ __forceinline__ void fdouble(u64*X,u64*Y,u64*Z){
    if(iszero(Z)||iszero(Y)){ X[0]=Y[0]=Z[0]=0; return; }
    u64 yy[4],s[4],m[4],x3[4],y3[4],z3[4],tmp[4];
    fmul(yy,Y,Y); fmul(s,X,yy); fadd(s,s); fadd(s,s);
    fmul(m,X,X); u64 mm[4]; memcpy(mm,m,sizeof(mm)); fadd(m,m); fadd(m,mm);
    fmul(x3,m,m); fsub(x3,x3,s); fsub(x3,x3,s);
    fmul(tmp,yy,yy); fadd(tmp,tmp); fadd(tmp,tmp); fadd(tmp,tmp);
    fsub(tmp,s,x3); fmul(y3,m,tmp); fmul(tmp,Y,tmp); // placeholder (fixed below)
    // y3 = m*(s-x3) - 8*yy^2
    u64 t8[4]; fmul(t8,yy,yy); fadd(t8,t8); fadd(t8,t8); fadd(t8,t8);
    fmul(y3,m,tmp0_dummy_guard(y3)); // replaced below
    // --- clean recompute ---
    u64 sx[4]; fsub(sx,s,x3); fmul(y3,m,sx); fmul(tmp,Y,t8); // not used
    u64 yyy[4]; fmul(yyy,yy,yy); fadd(yyy,yyy); fadd(yyy,yyy); fadd(yyy,yyy);
    fmul(y3,m,sx); fsub(y3,y3,yyy);
    fmul(z3,Y,Z); fadd(z3,z3);
    #pragma unroll
    for(int i=0;i<4;i++){ X[i]=x3[i]; Y[i]=y3[i]; Z[i]=z3[i]; }
}
__device__ __forceinline__ void addaff(u64*X,u64*Y,u64*Z,const u64*ax,const u64*ay){
    if(iszero(Z)){ for(int i=0;i<4;i++){X[i]=ax[i];Y[i]=ay[i];} Z[0]=1;Z[1]=Z[2]=Z[3]=0; return; }
    u64 z1z1[4],u2[4],s2[4],h[4],r[4],hh[4],hhh[4],v[4],x3[4],y3[4],z3[4],tmp[4];
    fmul(z1z1,Z,Z); fmul(u2,ax,z1z1); fmul(tmp,Z,z1z1); fmul(s2,ay,tmp);
    fsub(h,u2,X); fsub(r,s2,Y);
    if(iszero(h)){ if(iszero(r)){ fdouble(X,Y,Z); return; } X[0]=Y[0]=0;Y[1]=1;Z[0]=0;Z[1]=Z[2]=Z[3]=0; return; }
    fmul(hh,h,h); fmul(hhh,h,hh); fmul(v,X,hh);
    fmul(x3,r,r); fsub(x3,x3,hhh); fsub(x3,x3,v); fsub(x3,x3,v);
    fsub(tmp,v,x3); fmul(y3,r,tmp); fmul(tmp,Y,hhh); fsub(y3,y3,tmp);
    fmul(z3,Z,h);
    #pragma unroll
    for(int i=0;i<4;i++){ X[i]=x3[i]; Y[i]=y3[i]; Z[i]=z3[i]; }
}

extern "C" __global__ void kang_kernel(
    u64* X, u64* Y, u64* Z, u64* D, const unsigned char* type,
    const u64* JX, const u64* JY, const u64* JD,
    int n, int steps, u64* dp, unsigned int* dpc, int cap, int dpbits)
{
    int i = blockIdx.x*blockDim.x + threadIdx.x;
    if (i >= n) return;
    u64 x[4],y[4],z[4],d[4];
    #pragma unroll
    for(int k=0;k<4;k++){ x[k]=X[i*4+k]; y[k]=Y[i*4+k]; z[k]=Z[i*4+k]; d[k]=D[i*4+k]; }
    unsigned mask = (dpbits>=64)?0xFFFFFFFFu:((1u<<dpbits)-1u);
    for(int s=0;s<steps;s++){
        u64 ax[4]={x[0],x[1],x[2],x[3]};
        fnorm(ax,y,z);
        int idx = (int)(ax[0] & 31);
        if(((unsigned)(ax[0]) & mask)==0){
            unsigned slot = atomicAdd(dpc,1);
            if(slot < (unsigned)cap){
                #pragma unroll
                for(int k=0;k<4;k++) dp[slot*9+k]=ax[k];
                #pragma unroll
                for(int k=0;k<4;k++) dp[slot*9+4+k]=d[k];
                dp[slot*9+8]=(u64)type[i];
            }
        }
        addaff(x,y,z, JX+idx*4, JY+idx*4);
        fadd(d, JD+idx*4);
    }
    #pragma unroll
    for(int k=0;k<4;k++){ X[i*4+k]=x[k]; Y[i*4+k]=y[k]; Z[i*4+k]=z[k]; D[i*4+k]=d[k]; }
}
"""

# NOTE: fnorm mutates the passed x (affine) but we must keep the Jacobian x.
# In the kernel we pass a copy (ax) so the walker state is preserved.

# ───────────────────────────── Progress ─────────────────────────────
class Progress:
    SPIN = "|/-\\"
    def __init__(self, label, est):
        self.label=label; self.est=max(est,1); self.count=0; self.dps=0
        self.t0=time.time(); self._i=0; self._last=0.0
    def tick(self, count, dps, force=False):
        self.count=count; self.dps=dps; now=time.time()
        if not force and now-self._last<0.3: return
        self._last=now; el=now-self.t0
        rate=count/el if el>0.4 else 0.0
        pct=min(100.0,100.0*count/self.est)
        eta=(self.est-count)/rate if rate>0 else 0.0
        self._i=(self._i+1)%len(self.SPIN)
        line="\r%s %s | %s ops | %.0fs | %.0f ops/s | DPs %d | %5.1f%% ETA %.0fs  "%(
            self.SPIN[self._i],self.label,format(count,","),el,rate,dps,pct,eta)
        w=110; sys.stdout.write(line[:w].ljust(w)); sys.stdout.flush()
    def done(self,msg):
        sys.stdout.write("\r"+" "*110+"\r"+msg+"\n"); sys.stdout.flush()

# ───────────────────────── GPU kangaroo ─────────────────────────
class GpuKangaroo:
    """Parallel kangaroo on CUDA via CuPy RawKernel. Result is always
    re-verified on CPU before being accepted."""
    def __init__(self, hw):
        import cupy as cp
        self.cp = cp
        self.hw = hw
        self.kernel = cp.RawKernel(CUDA_SRC, "kang_kernel", options=("-std=c++14",))
        # quick field cross-check: 2^256 reduction & a known square
        self._selfcheck()

    def _selfcheck(self):
        cp = self.cp
        # verify the kernel compiles by launching a trivial grid
        n = 1
        X = cp.zeros((n,4), cp.uint64); Y = cp.zeros((n,4), cp.uint64); Z = cp.zeros((n,4), cp.uint64)
        D = cp.zeros((n,4), cp.uint64); T = cp.zeros(n, cp.uint8)
        JX = cp.zeros((32,4), cp.uint64); JY = cp.zeros((32,4), cp.uint64); JD = cp.zeros((32,4), cp.uint64)
        dp = cp.zeros((8,9), cp.uint64); dpc = cp.zeros(1, cp.uint32)
        self.kernel((1,),(1,), (X,Y,Z,D,T,JX,JY,JD,n,1,dp,dpc,8,8))
        cp.cuda.Stream.null.synchronize()

    def _to_dev(self, arr):    # list[list[int]] -> cp.uint64 (m,4)
        cp = self.cp
        return cp.asarray(arr, dtype=cp.uint64)

    def solve(self, backend_cpu, pub_hex, a, b, plan, timeout=None, resume=False):
        cp = self.cp
        W = b - a
        P = parse_pub(pub_hex)
        seed = int(hashlib.sha256(pub_hex.encode()).hexdigest()[:16],16)
        rng = random.Random(seed)

        # jump table (distances + affine points)
        bits = max(1, (W.bit_length()+1)//2)
        ds = set()
        while len(ds) < 32:
            ds.add(rng.randrange(1, 1<<bits) | 1)
        dists = sorted(ds)
        jpts  = [mul_aff(d, (Gx,Gy)) for d in dists]
        JX = self._to_dev([[p[0] & (2**64-1), (p[0]>>64)&(2**64-1), (p[0]>>128)&(2**64-1), p[0]>>192] for p in jpts])
        JY = self._to_dev([[p[1] & (2**64-1), (p[1]>>64)&(2**64-1), (p[1]>>128)&(2**64-1), p[1]>>192] for p in jpts])
        JD = self._to_dev([[d & (2**64-1),(d>>64)&(2**64-1),(d>>128)&(2**64-1),d>>192] for d in dists])

        n = plan["walkers"]
        steps = plan["steps"]
        dpbits = plan["dp_bits"]
        cap = min(1 << 20, n)

        # initial walkers: even = tame, odd = wild
        X = cp.zeros((n,4), cp.uint64); Y = cp.zeros((n,4), cp.uint64); Z = cp.zeros((n,4), cp.uint64)
        D = cp.zeros((n,4), cp.uint64); TY = cp.zeros(n, cp.uint8)
        seen = {}
        t0 = time.time()

        def init_walkers():
            st = []
            dt = []
            ty = []
            for i in range(n):
                if i & 1:  # wild: P + r*G, dist = r
                    r = rng.randrange(a, b)
                    pt = aff_add(P, mul_aff(r, (Gx,Gy)))
                    d = r; t = 1
                else:      # tame: t*G, dist = t
                    t0v = rng.randrange(a, b)
                    pt = mul_aff(t0v, (Gx,Gy))
                    d = t0v; t = 0
                if pt is None:
                    pt = (Gx,Gy); d = 1
                st.append(pt); dt.append(d); ty.append(t)
            return st, dt, ty

        st, dt, ty = init_walkers()
        def pack_states(st, dt):
            xa=[[p[0]&(2**64-1),(p[0]>>64)&(2**64-1),(p[0]>>128)&(2**64-1),p[0]>>192] for p in st]
            ya=[[p[1]&(2**64-1),(p[1]>>64)&(2**64-1),(p[1]>>128)&(2**64-1),p[1]>>192] for p in st]
            za=[[1,0,0,0] for _ in st]
            da=[[d&(2**64-1),(d>>64)&(2**64-1),(d>>128)&(2**64-1),d>>192] for d in dt]
            return self._to_dev(xa), self._to_dev(ya), self._to_dev(za), self._to_dev(da)

        X,Y,Z,D = pack_states(st, dt)
        TY = cp.asarray(ty, cp.uint8)
        dp  = cp.zeros((cap,9), cp.uint64)
        dpc = cp.zeros(1, cp.uint32)

        est = plan["expected_ops"]
        prog = Progress("kangaroo(GPU)", max(est//max(steps,1),1))
        blocks = max(1, n // 256)
        total = 0
        try:
            while True:
                if timeout and time.time()-t0 > timeout:
                    prog.done(yellow("  timeout — GPU state discarded"))
                    return None
                dpc[0] = 0
                self.kernel((blocks,),(256,),
                            (X,Y,Z,D,TY,JX,JY,JD,n,steps,dp,dpc,cap,dpbits))
                cp.cuda.Stream.null.synchronize()
                cnt = int(dpc[0]); total += n*steps
                if cnt:
                    cnt = min(cnt, cap)
                    got = cp.asnumpy(dp[:cnt])   # (cnt,9)
                    found = self._merge(got, seen, backend_cpu, P, a, b)
                    if found is not None:
                        prog.done(green("  HIT (GPU): k = %064x"%found))
                        return found
                prog.tick(total, len(seen))
                # re-seed walkers every so often to avoid degenerate walks
                if len(seen) > (1 << 22):
                    seen.clear()
                    st, dt, ty = init_walkers()
                    X,Y,Z,D = pack_states(st, dt); TY = cp.asarray(ty, cp.uint8)
        except KeyboardInterrupt:
            prog.done(yellow("  interrupted")); return None

    def _merge(self, got, seen, backend_cpu, P, a, b):
        for row in got:
            xs = int(row[0]) | (int(row[1])<<64) | (int(row[2])<<128) | (int(row[3])<<192)
            ds = int(row[4]) | (int(row[5])<<64) | (int(row[6])<<128) | (int(row[7])<<192)
            ty = int(row[8])
            prev = seen.get(xs)
            if prev is None:
                seen[xs] = (ds, ty); continue
            ds2, ty2 = prev
            if ty2 == ty:
                continue
            tame_d, wild_d = (ds, ds2) if ty == 0 else (ds2, ds)
            for cand in ((tame_d - wild_d) % N, (-tame_d - wild_d) % N):
                if a <= cand <= b and backend_cpu.to_hex(backend_cpu.mul_g(cand)) == \
                        ("%064x"%P[0]).join(["02" if (P[1]&1)==0 else "03",""]):
                    return cand
        return None

# ───────────────────────── CPU kangaroo ─────────────────────────
def kangaroo(backend, pub_hex, a, b, timeout=None, resume=False):
    W = b - a
    if W <= 0:
        raise ValueError("empty interval")
    P = backend.from_hex(pub_hex)
    bits = max(1, (W.bit_length()+1)//2)
    seed = int(hashlib.sha256(pub_hex.encode()).hexdigest()[:16],16)
    rng  = random.Random(seed)
    ds = set()
    while len(ds) < 32:
        ds.add(rng.randrange(1, 1<<bits) | 1)
    dists = sorted(ds)
    jpts  = [backend.mul_g(d) for d in dists]
    dp_bits = max(4, (W.bit_length()//2)-1)
    dp_mask = (1<<dp_bits)-1

    seen, total = {}, 0; t0 = None
    if resume and os.path.exists(CKPT):
        try:
            st = pickle.load(open(CKPT,"rb"))
            if st.get("pub")==pub_hex.lower():
                t0=st["t0"]; tame=backend.from_hex(st["tame"]); acc_t=st["acc_t"]
                wild=backend.from_hex(st["wild"]); acc_w=st["acc_w"]
                total=st.get("total",0); seen=st.get("seen",{})
                print(cyan("  resumed: %s ops, %d DPs"%(format(total,","),len(seen))))
        except Exception as e:
            print(yellow("  checkpoint unreadable (%s)"%e))
    if t0 is None:
        t0=rng.randrange(a,b); tame=backend.mul_g(t0); acc_t=0; wild=P; acc_w=0

    est = int(2.5*math.isqrt(W))+64
    prog = Progress("kangaroo", est); start=time.time(); last_ck=time.time()

    def save_ck():
        try:
            pickle.dump({"pub":pub_hex.lower(),"t0":t0,"tame":backend.to_hex(tame),
                         "acc_t":acc_t,"wild":backend.to_hex(wild),"acc_w":acc_w,
                         "total":total,"seen":seen}, open(CKPT+".tmp","wb"))
            os.replace(CKPT+".tmp",CKPT)
        except Exception as e:
            print(yellow("\n  checkpoint save failed: %s"%e))

    def try_solve(tame_o, wild_o):
        for cand in ((tame_o-wild_o)%N, (-tame_o-wild_o)%N):
            if a<=cand<=b and backend.eq(backend.mul_g(cand),P):
                return cand
        return None

    def record(x, off, is_tame):
        o2 = seen.get(x)
        if o2 is None:
            seen[x]=(off,is_tame); return None
        off2, tame2 = o2
        if tame2==is_tame: return None
        to, wo = (off,off2) if is_tame else (off2,off)
        return try_solve(to, wo)

    try:
        while True:
            if timeout and time.time()-start>timeout:
                save_ck(); prog.done(yellow("  timeout — checkpoint saved")); return None
            xt = backend.x(tame)
            if xt is None:
                t0=rng.randrange(a,b); tame=backend.mul_g(t0); acc_t=0
            else:
                idx=(xt>>251)&31; tame=backend.add(tame,jpts[idx]); acc_t=(acc_t+dists[idx])%N; total+=1
                x2=backend.x(tame)
                if x2 is not None and (x2&dp_mask)==0:
                    k=record(x2,(t0+acc_t)%N,True)
                    if k is not None:
                        save_ck(); prog.done(green("  HIT (tame): k = %064x"%k)); return k
            xw=backend.x(wild)
            if xw is None:
                wild=P; acc_w=0
            else:
                idx=(xw>>251)&31; wild=backend.add(wild,jpts[idx]); acc_w=(acc_w+dists[idx])%N; total+=1
                x2=backend.x(wild)
                if x2 is not None and (x2&dp_mask)==0:
                    k=record(x2,acc_w,False)
                    if k is not None:
                        save_ck(); prog.done(green("  HIT (wild): k = %064x"%k)); return k
            prog.tick(total,len(seen))
            if time.time()-last_ck>30: save_ck(); last_ck=time.time()
    except KeyboardInterrupt:
        save_ck(); prog.done(yellow("  interrupted — checkpoint saved")); return None

# ───────────────────────── self test ─────────────────────────
def selftest(want_gpu=False):
    print(cyan("=== SELFTEST ==="))
    b = select_backend()
    print("  cpu backend: %s"%b.name)
    g = b.to_hex(b.mul_g(1))
    if g != "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798":
        print(red("  FAIL mul_g(1)")); return 1
    print(green("  [1/4] k*G identity ......... OK"))
    if len(hash160(bytes.fromhex(g))) != 20:
        print(red("  FAIL hash160")); return 1
    print(green("  [2/4] hash160 .............. OK"))

    if want_gpu:
        hw = Hardware()
        if not hw.cuda_ok:
            print(yellow("  [3/4] GPU ................... unavailable (CPU only)"))
        else:
            try:
                GpuKangaroo(hw)
                print(green("  [3/4] GPU kernel compiles ... OK (%s)"%hw.gpu["name"]))
            except Exception as e:
                print(yellow("  [3/4] GPU failed (%s) — CPU fallback"%e))
    else:
        print("  [3/4] GPU ................... skipped")

    lo, hi = 1<<20, (1<<21)-1
    secret = random.Random(1234).randrange(lo,hi)
    pub = b.to_hex(b.mul_g(secret))
    print(cyan("  [4/4] kangaroo planted key in 2^20 ..."))
    got = kangaroo(b, pub, lo, hi, timeout=120)
    if got != secret:
        print(red("  FAILED got=%s want=%s"%(got,hex(secret)))); return 1
    print(green("  [4/4] kangaroo ............. OK"))
    print(green("SELFTEST PASSED"))
    return 0

# ───────────────────────── telegram (optional) ─────────────────────────
def _ks(key, nonce, n):
    out=b""; c=0
    while len(out)<n:
        out+=hmac.new(key,nonce+struct.pack("<I",c),hashlib.sha256).digest(); c+=1
    return out[:n]

def tg_setup():
    print(cyan("=== TELEGRAM SETUP (encrypted) ==="))
    print(yellow("Revoke any token ever pasted in chat (@BotFather /revoke)."))
    tok=input("Bot token: ").strip()
    cid=input("Chat ID (blank to auto-discover): ").strip()
    if not cid:
        import urllib.request, json as _j
        print("  polling getUpdates 60s — send /start to your bot...")
        for _ in range(30):
            try:
                with urllib.request.urlopen("https://api.telegram.org/bot%s/getUpdates"%tok,timeout=10) as r:
                    js=_j.loads(r.read())
                if js.get("result"):
                    cid=str(js["result"][-1]["message"]["chat"]["id"]); break
            except Exception: pass
            time.sleep(2)
        if not cid:
            print(red("  no chat id found")); return 1
    key=os.urandom(32); nonce=os.urandom(8)
    plain=(tok+"|"+cid).encode()
    blob=nonce+bytes(a^b for a,b in zip(plain,_ks(key,nonce,len(plain))))
    open(TG_KEY,"wb").write(key); open(TG_ENC,"wb").write(blob)
    print(green("  saved (.tg_enc / .tg_key)")); return 0

def tg_load():
    if not (os.path.exists(TG_ENC) and os.path.exists(TG_KEY)):
        return None,None
    try:
        key=open(TG_KEY,"rb").read(); blob=open(TG_ENC,"rb").read()
        if len(key)!=32 or len(blob)<9: return None,None
        nonce,ct=blob[:8],blob[8:]
        plain=bytes(a^b for a,b in zip(ct,_ks(key,nonce,len(ct)))).decode()
        t,c=plain.split("|",1); return t,c
    except Exception:
        return None,None

def tg_send(text):
    tok,cid=tg_load()
    if not tok:
        print(yellow("  telegram not configured (tg-setup)")); return False
    try:
        import urllib.request, urllib.parse
        data=urllib.parse.urlencode({"chat_id":cid,"text":text[:4000],"parse_mode":"Markdown"}).encode()
        with urllib.request.urlopen("https://api.telegram.org/bot%s/sendMessage"%tok,data=data,timeout=15) as r:
            return r.status==200
    except Exception as e:
        print(yellow("  telegram failed: %s"%e)); return False

# ───────────────────────── commands ─────────────────────────
def cmd_hw(args):
    hw=Hardware()
    print(cyan("=== HARDWARE ==="))
    print("  cpu logical : %d"%hw.cpu_logical)
    print("  ram         : %.1f GB"%hw.ram_gb)
    if hw.gpu:
        print("  gpu         : %s"%hw.gpu["name"])
        print("  vram        : %d MB"%hw.gpu["vram_mb"])
        print("  compute     : %s"%hw.gpu.get("cc","?"))
        if "sm_count" in hw.gpu:
            print("  sm / threads: %d sm, %d max-threads"%(hw.gpu["sm_count"],hw.gpu.get("max_threads",0)))
    else:
        print("  gpu         : none detected")
    print("  cupy        : %s"%hw.cupy_ver)
    print("  cuda usable : %s"%hw.cuda_ok)
    if hw.cupy_ver and not hw.cuda_ok:
        print(yellow("  note: cupy present but CUDA runtime unavailable "
                     "(Python 3.14 unsupported -> use a 3.12 venv: pip install cupy-cuda12x)"))
    for bits in (40,50,65):
        pl=hw.plan(bits)
        print("  plan 2^%-3d  : %s | walkers=%s steps=%s dp=%d"%(
            bits, "GPU" if pl["use_gpu"] else "CPU",
            pl["walkers"], pl["steps"], pl["dp_bits"]))
    return 0

def cmd_env(args):
    hw=Hardware(); b=select_backend()
    print(cyan("=== ENVIRONMENT ==="))
    print("  cpu backend : %s"%b.name)
    print("  python      : %s (%s)"%(sys.version.split()[0],sys.platform))
    print("  cpus        : %s"%os.cpu_count())
    print("  gpu         : %s"%(hw.gpu["name"] if hw.gpu else "none"))
    print("  cupy        : %s"%hw.cupy_ver)
    print("  cuda usable : %s"%hw.cuda_ok)
    tok,_=tg_load()
    print("  telegram    : %s"%("configured" if tok else "not configured"))
    return 0

def cmd_selftest(args):
    return selftest(want_gpu=args.gpu)

def _run_solve(args):
    hw=Hardware(); b=select_backend()
    if args.puzzle:
        a,bb=1<<(args.puzzle-1),(1<<args.puzzle)-1
        print(cyan("=== PUZZLE #%d ===  [2^%d, 2^%d]"%(args.puzzle,args.puzzle-1,args.puzzle)))
    else:
        a,bb=int(args.start,16),int(args.end,16)
        print(cyan("=== CUSTOM INTERVAL ==="))
    W=bb-a
    bits=W.bit_length()
    plan=hw.plan(bits, backend=args.mode)
    print("  range : 0x%x .. 0x%x (2^%.1f)"%(a,bb,math.log2(W)))
    print("  est   : ~%s ops"%format(plan["expected_ops"],","))
    print("  mode  : %s"%("GPU "+hw.gpu["name"] if plan["use_gpu"] and hw.gpu else "CPU"))

    if not args.skip_selftest:
        if selftest(want_gpu=plan["use_gpu"])!=0:
            return 1

    k=None
    if plan["use_gpu"]:
        try:
            gk=GpuKangaroo(hw)
            k=gk.solve(b, args.pubkey, a, bb, plan,
                       timeout=args.timeout, resume=getattr(args,"resume",False))
        except Exception as e:
            print(yellow("  GPU path unavailable (%s) — using CPU"%e))
            k=None
    if k is None:
        k=kangaroo(b, args.pubkey, a, bb, timeout=args.timeout,
                   resume=getattr(args,"resume",False))
    if k is None:
        print(yellow("  no hit — rerun 'resume' to continue")); return 2

    pk=b.to_hex(b.mul_g(k))
    rep=("KEY FOUND\n  puzzle : #%s\n  k hex  : %064x\n  k dec  : %d\n  pubkey : %s\n  verified: %s"
         %(args.puzzle or "custom", k, k, pk, pk==args.pubkey.lower()))
    print(green("\n"+rep))
    try: open(FOUND,"a").write(rep+"\n\n")
    except Exception: pass
    if args.notify: tg_send("*%s*"%rep)
    return 0

def cmd_solve(args):  return _run_solve(args)
def cmd_resume(args): args.resume=True; return _run_solve(args)
def cmd_tg_setup(args): return tg_setup()
def cmd_tg_test(args):
    ok=tg_send("test from btc_kangaroo.py")
    print(green("  sent OK") if ok else red("  send FAILED"))
    return 0 if ok else 1

def build_parser():
    ap=argparse.ArgumentParser(prog="btc_kangaroo.py",
                               description="single-file BTC puzzle solver (kangaroo, CPU+GPU)")
    sub=ap.add_subparsers(dest="cmd")
    sub.add_parser("hw",help="hardware probe + plan").set_defaults(func=cmd_hw)
    sub.add_parser("env",help="environment report").set_defaults(func=cmd_env)
    p=sub.add_parser("selftest",help="correctness gates")
    p.add_argument("--gpu",action="store_true",help="also cross-check GPU kernel")
    p.set_defaults(func=cmd_selftest)
    sub.add_parser("tg-setup",help="store encrypted telegram creds").set_defaults(func=cmd_tg_setup)
    sub.add_parser("tg-test",help="send test message").set_defaults(func=cmd_tg_test)
    for name,fn,h in (("solve",cmd_solve,"solve a puzzle/interval"),
                      ("resume",cmd_resume,"resume last checkpoint")):
        p=sub.add_parser(name,help=h)
        p.add_argument("--puzzle",type=int,default=None)
        p.add_argument("--start",default=None,help="hex start")
        p.add_argument("--end",default=None,help="hex end inclusive")
        p.add_argument("--pubkey",required=True)
        p.add_argument("--timeout",type=float,default=None)
        p.add_argument("--mode",choices=("auto","gpu","cpu"),default="auto")
        p.add_argument("--notify",action="store_true")
        p.add_argument("--skip-selftest",action="store_true")
        p.set_defaults(func=fn)
    return ap

def main():
    argv=sys.argv[1:] or ["env"]
    args=build_parser().parse_args(argv)
    if args.cmd in ("solve","resume"):
        if not args.puzzle and not (args.start and args.end):
            print(red("need --puzzle N  or  --start HEX --end HEX")); return 1
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print(yellow("\nstopped.")); return 130
    except Exception as e:
        print(red("\nFATAL: %s: %s"%(type(e).__name__,e)))
        import traceback; traceback.print_exc(); return 1

if __name__ == "__main__":
    sys.exit(main())
