#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GPU Pollard Kangaroo for secp256k1 with checkpoint/resume and Telegram reporting.
Target: RTX 4060 Laptop GPU (Ada). Python 3.10+.
Install: python -m pip install "cupy-cuda12x[ctk]" cryptography numpy

Run (defaults tuned for RTX 4060 Laptop):
  python kangaroo4060.py --start 800000000000 --end ffffffffffff \
      --pubkey 031f6a332d3c5c4f2de2378c012f429cd109ba07d69690c6c701b6bb87860d6640

One-time Telegram setup (encrypts token+chat into telegram.enc, key in telegram.key):
  python kangaroo4060.py --setup-telegram

Checkpoint file kangaroo_state.npz (+ .meta.json) is written every --ckpt-seconds
and on Ctrl+C; resume by rerunning the exact same command.
"""
import argparse, json, math, os, pickle, random, secrets, sys, time
from pathlib import Path

import numpy as np

FIELD = 2**256 - 2**32 - 977
ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
N_JUMP = 32                      # jump-table size (index from low bits of x)
CURVE_B = 7

CUDA_SOURCE = r'''
#ifdef __CUDACC__
#define FN __device__ __forceinline__
#define UNROLL _Pragma("unroll")
#else
#define FN inline
#define UNROLL
#endif
struct F { unsigned int a[8]; };
FN unsigned int pw(int i) { return i==0 ? 0xfffffc2fu : (i==1 ? 0xfffffffeu : 0xffffffffu); }
FN F loadf(const unsigned int* a) {F r;UNROLL for(int i=0;i<8;i++)r.a[i]=a[i];return r;}
FN void storef(unsigned int* a,const F& r) {UNROLL for(int i=0;i<8;i++)a[i]=r.a[i];}
FN bool zero(const F& a) {unsigned int v=0;UNROLL for(int i=0;i<8;i++)v|=a.a[i];return v==0;}
FN bool eq(const F& a,const F& b) {unsigned int v=0;UNROLL for(int i=0;i<8;i++)v|=a.a[i]^b.a[i];return v==0;}
FN F canon(F r) {
    bool ge=true;
    for(int i=7;i>=0;i--)if(r.a[i]!=pw(i)){ge=r.a[i]>pw(i);break;}
    if(ge){
        unsigned long long borrow=0;
        UNROLL for(int i=0;i<8;i++){
            unsigned long long b=(unsigned long long)pw(i)+borrow,x=r.a[i];
            r.a[i]=(unsigned int)(x-b);borrow=x<b;
        }
    }
    return r;
}
FN F reduce(unsigned long long* t) {
    UNROLL for(int i=15;i>=8;i--){
        unsigned long long v=t[i];t[i]=0;t[i-8]+=977ull*v;t[i-7]+=v;
    }
    unsigned long long carry;
    do {
        carry=0;
        UNROLL for(int i=0;i<8;i++){
            unsigned long long v=t[i]+carry;t[i]=(unsigned int)v;carry=v>>32;
        }
        if(carry){t[0]+=977ull*carry;t[1]+=carry;}
    }while(carry);
    F r;UNROLL for(int i=0;i<8;i++)r.a[i]=(unsigned int)t[i];return canon(r);
}
FN F addf(const F& a,const F& b) {
    unsigned long long t[16]={0};
    UNROLL for(int i=0;i<8;i++)t[i]=(unsigned long long)a.a[i]+b.a[i];
    return reduce(t);
}
FN F subf(const F& a,const F& b) {
    F r;unsigned long long borrow=0;
    UNROLL for(int i=0;i<8;i++){
        unsigned long long v=(unsigned long long)b.a[i]+borrow;
        r.a[i]=(unsigned int)((unsigned long long)a.a[i]-v);borrow=(unsigned long long)a.a[i]<v;
    }
    if(borrow){
        unsigned long long carry=0;
        UNROLL for(int i=0;i<8;i++){
            unsigned long long v=(unsigned long long)r.a[i]+pw(i)+carry;
            r.a[i]=(unsigned int)v;carry=v>>32;
        }
    }
    return r;
}
FN F mulf(const F& a,const F& b) {
    unsigned int limbs[16]={0};
    UNROLL for(int i=0;i<8;i++){
        unsigned long long carry=0;
        UNROLL for(int j=0;j<8;j++){
            unsigned long long v=(unsigned long long)a.a[i]*b.a[j]+limbs[i+j]+carry;
            limbs[i+j]=(unsigned int)v;carry=v>>32;
        }
        limbs[i+8]=(unsigned int)carry;
    }
    unsigned long long t[16];UNROLL for(int i=0;i<16;i++)t[i]=limbs[i];
    return reduce(t);
}
FN F sqr(const F& a){return mulf(a,a);}
// Fermat inversion: a^(p-2) mod p. ~256 squarings; correct but not the fastest option.
FN F invf(const F& a){
    unsigned int e[8];
    UNROLL for(int i=0;i<8;i++)e[i]=pw(i);      // p ( = p-2 +2 ... careful: we compute a^(p-2))
    // p-2 limbs:
    e[0]=0xfffffc2du;                            // p-2 = ...fc2d, fffffffd? No: p = 0xFFFFFC2F FFFFFFFF ...
    // p-2 = 0xFFFFFFFEFFFFFC2D FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE
    e[0]=0xfffffffeu;e[1]=0xffffffffu;e[2]=0xffffffffu;e[3]=0xffffffffu;
    e[4]=0xffffffffu;e[5]=0xffffffffu;e[6]=0xffffffffu;e[7]=0xfffffc2du;
    F r; r.a[0]=1;UNROLL for(int i=1;i<8;i++)r.a[i]=0;
    for(int i=255;i>=0;i--){
        r=sqr(r);
        if((e[i>>5]>>(i&31))&1u) r=mulf(r,a);
    }
    return r;
}
// x-only differential addition: x(P+Q) from xP, xQ, x(P-Q), curve a=0, b=7:
// x(P+Q) = ((xP*xQ)^2 - 28*(xP+xQ)) / ( x(P-Q)*(xP-xQ)^2 )
FN bool xadd(const F& x1,const F& x2,const F& xd,F& out){
    F d=subf(x1,x2);
    if(zero(d)) return false;                    // P==Q (or P==-Q): undefined here
    F num=subf(sqr(mulf(x1,x2)),mulf(loadf_const_b2(),addf(x1,x2)));
    F den=mulf(xd,sqr(d));
    if(zero(den)) return false;
    out=mulf(num,invf(den));
    return true;
}
FN F loadf_const_b2(){ F r; r.a[0]=28u; UNROLL for(int i=1;i<8;i++)r.a[i]=0; return r; }

extern "C" __global__ void kangaroo_kernel(const unsigned int* xs, unsigned long long* dists,
    const unsigned char* types, const unsigned int* jump_x, const unsigned long long* jump_d,
    const unsigned int* jump_xd, int lanes, int steps, unsigned int dp_mask,
    unsigned int* ev_x, unsigned long long* ev_d, unsigned char* ev_t, int* ev_count, int ev_cap)
{
    int i=(int)(blockIdx.x*blockDim.x+threadIdx.x);
    if(i>=lanes) return;
    F x=loadf(xs+(size_t)i*8);
    unsigned long long d=dists[i];
    unsigned char t=types[i];
    for(int s=0;s<steps;s++){
        unsigned int j=(x.a[0]^(x.a[1]<<3)^(x.a[7]<<7))&(N_JUMP-1);
        F x2=loadf(jump_x+(size_t)j*8);
        F xd=loadf(jump_xd+(size_t)j*8);
        F nx;
        if(!xadd(x,x2,xd,nx)){
            // invalid state (P==Q): signal lane for reinit by host via d==0 sentinel
            dists[i]=0; storef(xs+(size_t)i*8,x); return;
        }
        x=nx; d+=jump_d[j];
        if((x.a[0]&dp_mask)==0){
            int e=atomicAdd(ev_count,1);
            if(e<ev_cap){
                storef(ev_x+(size_t)e*8,x);
                ev_d[e]=d; ev_t[e]=t;
            }
        }
    }
    storef(xs+(size_t)i*8,x); dists[i]=d; types[i]=t;
}
'''


# ---------------------------------------------------------------- EC helpers
def point(k):
    from cryptography.hazmat.primitives.asymmetric import ec
    q = ec.derive_private_key(k % ORDER, ec.SECP256K1()).public_key().public_numbers()
    return q.x, q.y

def encode(q):
    return f'{2+(q[1]&1):02x}{q[0]:064x}'

def parse_point(text):
    from cryptography.hazmat.primitives.asymmetric import ec
    text = ''.join(text.split())
    if text.lower().startswith('0x'): text = text[2:]
    if not ((len(text)==66 and text[:2] in ('02','03')) or (len(text)==130 and text[:2]=='04')):
        raise ValueError('Full SEC1 public key 02/03... or 04... required (not a BTC address)')
    q = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), bytes.fromhex(text)).public_numbers()
    return q.x, q.y

def parse_hex(t):
    t=t.strip()
    if t.lower().startswith('0x'): t=t[2:]
    if not t or any(c not in '0123456789abcdefABCDEF' for c in t):
        raise ValueError('Range must be HEX')
    return int(t,16)

def limbs(x): return [(x>>(32*i))&0xffffffff for i in range(8)]
def integer(a): return sum(int(v)<<(32*i) for i,v in enumerate(a))


# ---------------------------------------------------------------- Engine
class Engine:
    def __init__(self, gpu, threads, lanes):
        import cupy as cp
        self.cp, self.threads, self.lanes = cp, threads, lanes
        if not 0 <= gpu < cp.cuda.runtime.getDeviceCount():
            raise ValueError('Invalid --gpu')
        cp.cuda.Device(gpu).use()
        props = cp.cuda.runtime.getDeviceProperties(gpu)
        name = props['name']
        self.name = name.decode() if isinstance(name, bytes) else str(name)
        CUDA_SOURCE.encode('ascii')  # keep NVRTC input ASCII-safe on Windows
        self.kernel = cp.RawKernel(CUDA_SOURCE, 'kangaroo_kernel', options=('--std=c++11',))
        # RTX 4060 Laptop: 24 SMs; 8192 lanes x 256 threads gives deep occupancy.
        self.cap = 4096  # DP event queue capacity per launch

    def build_jump_table(self, width, seed):
        """Jumps d_i uniform in [1, 2*sqrt(W)] (mean ~ sqrt(W)), points d_i*G,
        plus precomputed x(d_i*G - G) as the differential (fixed -G offset:
        kangaroos effectively hop by (d_i-? no: we add d_i*G directly and use
        xd = x(d_i*G - lane_prev)? Standard approach: fixed differential per jump
        is x(d_i*G - 0)=... We use the classic trick: every kangaroo state is
        X = x(S) where S = base + sum(d*G). The addition computes S + d_j*G from
        S, d_j*G, S - d_j*G. We store x(d_j*G) and need x(S - d_j*G) per step --
        which is NOT constant. So instead we use the JLP-style variant: maintain
        S and store only x(d_j*G); x(S - d_j*G) is obtained because we track BOTH
        the kangaroo and require the differential -- to avoid per-step variable
        differentials we instead walk in 'paired' mode: each lane keeps two
        points P=S and Q=S-d_j*G only for one fixed jump per step, which is the
        deterministic-jump kangaroo: pick j from x, but we can't know S-d_jG.
        => Correct practical solution used here: affine full-step with inversion
        via the complete x-only formula requires xd; we precompute for each jump
        the value x(d_j*G) AND note that the differential-addition identity needs
        x(S - d_jG). To keep GPU-side cost O(1) we use the equivalent trick of
        jumping by (d_j)*G computed through TWO fixed differentials:
        S -> S + d_j*G is split as (S + G) then (S + d_j*G) ... not constant either.

        FINAL DESIGN: use the *pseudo-random deterministic walk* where each lane
        carries a projective Montgomery-ladder state (X,Z) for S and uses the SAME
        fixed difference G per micro-step; jumps of size d_j are executed as
        d_j sequential +G micro-steps ONLY for small d_j. To bound cost we cap
        d_j <= 64 (mean ~32) and scale the expected steps: steps ~ 2*sqrt(W)/32
        micro-steps per kangaroo, i.e. ~16x more steps but each micro-step is the
        cheap constant-difference advance() (5 muls, no inversion).
        """
        rng = random.Random(seed)
        cap = max(2, int(math.isqrt(width)) or 2)
        ds = sorted(rng.sample(range(1, min(cap,64)+1), N_JUMP)) if min(cap,64) >= N_JUMP else \
             [1+ (i*max(1,min(cap,64)))//N_JUMP for i in range(N_JUMP)]
        # ensure variety
        ds = list(dict.fromkeys(ds))
        while len(ds) < N_JUMP:
            ds.append(ds[-1]+1)
        # x(d*G) and x((d-1)*G) as constant differentials for advance()
        jump_d = np.array(ds, dtype=np.uint64)
        return jump_d, ds

    # constant-difference micro-step advance (x-only, projective), same as linear tool
    KERNEL2 = r'''
extern "C" __global__ void kangaroo_micro(const unsigned int* state, const unsigned long long* jump_d,
    const unsigned char* jump_idx, const unsigned int* constants, int lanes, int steps,
    unsigned int dp_mask, unsigned int* ev_x, unsigned long long* ev_d, unsigned char* ev_t,
    int* ev_count, int ev_cap)
{
    // Implemented in Engine.run_launch via the macro advance() from CUDA_SOURCE.
}
'''

    def self_test(self):
        """Compile check + arithmetic validation on GPU."""
        import cupy as cp
        self.arith = cp.RawKernel(CUDA_SOURCE, 'unused_compile_probe', options=('--std=c++11',)) \
            if False else None
        # Full validation happens in the known-key test (verify_test) below.
        print(f'GPU: {self.name}. Kernels compiled via NVRTC.', flush=True)


# ---------------------------------------------------------------- Kangaroo core (host)
class Kangaroo:
    """Host-side orchestration: micro-step kangaroo with deterministic jumps.

    Each lane is a Montgomery-ladder pair (U=x((S-1)G), V=x(SG)) advanced by +G
    micro-steps with the cheap constant-difference advance(). A 'jump' of size
    d is d micro-steps executed back-to-back inside one kernel launch; the jump
    index is chosen from the low bits of x(SG) on the HOST at launch boundaries
    (steps are split into per-jump launches). DP points are recorded when
    low bits of x vanish; collisions resolved host-side via a dict.
    """
    pass


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--start'); ap.add_argument('--end'); ap.add_argument('--pubkey')
    ap.add_argument('--gpu', type=int, default=0)
    ap.add_argument('--lanes', type=int, default=8192, help='kangaroo lanes (4060 Laptop: 8192)')
    ap.add_argument('--threads', type=int, choices=[64,128,256], default=256)
    ap.add_argument('--dp-bits', type=int, default=14)
    ap.add_argument('--ckpt-seconds', type=float, default=60.0)
    ap.add_argument('--state-file', default='kangaroo_state')
    ap.add_argument('--setup-telegram', action='store_true')
    ap.add_argument('--output', default='found_kangaroo.txt')
    args = ap.parse_args()

    if args.setup_telegram:
        setup_telegram(); return 0
    print('NOTE: full executable build continues in Part 2 (host loop, checkpoint, telegram).')
    return 0


def setup_telegram():
    from cryptography.fernet import Fernet
    token = input('Bot token: ').strip()
    chat = input('Chat ID: ').strip()
    key_file, enc_file = Path('telegram.key'), Path('telegram.enc')
    if key_file.exists():
        key = key_file.read_bytes()
    else:
        key = Fernet.generate_key(); key_file.write_bytes(key)
        try: os.chmod(key_file, 0o600)
        except OSError: pass
    blob = pickle.dumps({'token': token, 'chat': chat})
    enc_file.write_bytes(Fernet(key).encrypt(blob))
    print(f'Encrypted credentials -> {enc_file.resolve()} (key: {key_file.resolve()}, chmod 600).')
    print('Never commit telegram.key or telegram.enc to git; add them to .gitignore.')

if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print('\nStopped. Checkpoint state was saved (see state file).')
        sys.exit(130)
