#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Experimental CUDA search for k where P=kG (secp256k1).
Python 3.10+, NVIDIA GPU, compatible driver.
Install: python -m pip install "cupy-cuda12x[ctk]" cryptography
Run: python xz_gpu32.py --start 1 --end 1000 --pubkey 02... --gpu 0
Without range/key parameters: interactive input.
Bounds are HEX, inclusive. --lanes sets independent GPU chains.
This is portable self-contained arithmetic, not an optimized speed record.
Modes: sequential, random-start (new starting point), random (blocks without repeats).
--autotune selects threads/steps. --seed reproduces ordering but does not save progress.
No checkpoint/resume. Ctrl+C is handled between short CUDA launches.
"""
import argparse
from pathlib import Path
import random
import math
import secrets
import statistics
import sys
import time

FIELD = 2**256 - 2**32 - 977
ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# 8 limbs of 32 bits, little endian; no 16-bit splitting.
# 64-bit accumulators; we use 2^256 == 2^32+977 (mod p).
# The same arithmetic code is compiled on CPU for verification and in CUDA.
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
FN bool eq(const F& a,const F& b) {unsigned int v=0;UNROLL for(int i=0;i<8;i++)v|=a.a[i]^b.a[i];return v==0;}
FN bool zero(const F& a) {unsigned int v=0;UNROLL for(int i=0;i<8;i++)v|=a.a[i];return v==0;}
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
    // Each sum is bounded by (2^32-1)^2+2*(2^32-1) = 2^64-1.
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
FN void advance(F& u,F& v,F& x,F& z,const F& c) {
    F nx=mulf(v,subf(mulf(x,x),mulf(mulf(c,z),addf(x,z))));
    F d=subf(x,z);F nz=mulf(u,mulf(d,d));u=x;v=z;x=nx;z=nz;
}
FN int walk(unsigned int* state,unsigned int limit,const F& c,const F& s,unsigned int* processed) {
    F u=loadf(state),v=loadf(state+8),x=loadf(state+16),z=loadf(state+24);
    int hit=-1;unsigned int count=0;
    for(unsigned int j=0;j<limit;j++){
        if(zero(z)){hit=-2;break;}
        bool match=eq(x,mulf(s,z));advance(u,v,x,z,c);count++;
        if(match){hit=(int)j;break;}
    }
    storef(state,u);storef(state+8,v);storef(state+16,x);storef(state+24,z);
    *processed=count;return hit;
}
#ifdef __CUDACC__
extern "C" __global__ void scan_kernel(unsigned int* state,const unsigned int* limits,
 const unsigned int* constants,int lanes,int* status){
    int i=(int)(blockIdx.x*blockDim.x+threadIdx.x);if(i>=lanes)return;
    unsigned int count=0;
    int hit=walk(state+(unsigned long long)i*32,limits[i],loadf(constants),loadf(constants+8),&count);
    status[i*2]=hit;status[i*2+1]=(int)count;
}
extern "C" __global__ void arithmetic_kernel(const unsigned int* a,const unsigned int* b,unsigned int* out,int count){
    int i=(int)(blockIdx.x*blockDim.x+threadIdx.x);if(i>=count)return;
    F x=loadf(a+i*8),y=loadf(b+i*8);
    storef(out+i*24,addf(x,y));storef(out+i*24+8,subf(x,y));storef(out+i*24+16,mulf(x,y));
}
#else
extern "C" void cpu_arithmetic(const unsigned int* a,const unsigned int* b,unsigned int* out){
    F x=loadf(a),y=loadf(b);storef(out,addf(x,y));storef(out+8,subf(x,y));storef(out+16,mulf(x,y));
}
extern "C" int cpu_walk(unsigned int* state,unsigned int limit,const unsigned int* constants,unsigned int* processed){
    return walk(state,limit,loadf(constants),loadf(constants+8),processed);
}
#endif
'''


def point(k):
    from cryptography.hazmat.primitives.asymmetric import ec
    q = ec.derive_private_key(k, ec.SECP256K1()).public_key().public_numbers()
    return q.x, q.y


def encode(q):
    return f'{2+(q[1]&1):02x}{q[0]:064x}'


def parse_point(text):
    from cryptography.hazmat.primitives.asymmetric import ec
    text = ''.join(text.split())
    if text.lower().startswith('0x'):
        text = text[2:]
    if not ((len(text)==66 and text[:2] in ('02','03')) or (len(text)==130 and text[:2]=='04')):
        raise ValueError('A full SEC1 public key 02/03... or 04... is required, not a BTC address')
    q = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), bytes.fromhex(text)).public_numbers()
    return q.x, q.y


def parse_hex(text):
    text = text.strip()
    if text.lower().startswith('0x'):
        text = text[2:]
    if not text or any(c not in '0123456789abcdefABCDEF' for c in text):
        raise ValueError('The range must be given as HEX numbers')
    return int(text,16)


def limbs(x):
    return [(x >> (32*i)) & 0xffffffff for i in range(8)]


def integer(a):
    return sum(int(v) << (32*i) for i,v in enumerate(a))


def initial(k, ih):
    return limbs(point(k-1)[0]*ih % FIELD)+limbs(1)+limbs(point(k)[0]*ih % FIELD)+limbs(1)


def partitions(start,end,lanes):
    size,extra=divmod(end-start+1,lanes)
    for i in range(lanes):
        length=size+(i<extra)
        yield start,start+length-1
        start+=length


class Engine:
    def __init__(self, gpu, threads):
        import cupy as cp
        import numpy as np
        self.cp,self.np,self.threads=cp,np,threads
        if not 0 <= gpu < cp.cuda.runtime.getDeviceCount():
            raise ValueError('Invalid --gpu: device not found')
        cp.cuda.Device(gpu).use()
        props=cp.cuda.runtime.getDeviceProperties(gpu)
        name=props['name']
        self.name=name.decode() if isinstance(name,bytes) else str(name)
        # RawKernel uses NVRTC: Visual Studio/nvcc are not needed for this file.
        # Keep the compiler input ASCII for Windows locale-dependent file writes.
        CUDA_SOURCE.encode('ascii')
        self.scan=cp.RawKernel(CUDA_SOURCE,'scan_kernel',options=('--std=c++11',))
        self.arithmetic=cp.RawKernel(CUDA_SOURCE,'arithmetic_kernel',options=('--std=c++11',))
        self.h=point(1)[0]
        self.ih=pow(self.h,-1,FIELD)
        self.c=28*pow(self.ih,3,FIELD)%FIELD

    def constants(self,target):
        return self.cp.asarray(limbs(self.c)+limbs(target[0]*self.ih%FIELD),dtype=self.np.uint32)

    def launch(self,state,limits,constants):
        cp,np=self.cp,self.np
        size=len(limits)
        if not hasattr(self,'buffers') or self.buffers[0].shape[0]!=size:
            self.buffers=(cp.empty((size,2),dtype=np.int32),cp.empty(size,dtype=np.uint32))
        status,limits_device=self.buffers
        limits_device.set(np.asarray(limits,dtype=np.uint32))
        self.scan(((size+self.threads-1)//self.threads,), (self.threads,),
                  (state,limits_device,constants,np.int32(size),status))
        # One synchronized transfer, buffers reused between launches.
        host=status.get()
        return host[:,0],host[:,1]

    def self_test(self):
        cp,np=self.cp,self.np
        rng=random.Random(1977)
        edges=[0,1,2,65535,65536,2**32-1,2**32,2**64-1,2**128-1,FIELD-2,FIELD-1]
        pairs=[(a,b) for a in edges for b in edges]
        pairs += [(rng.randrange(FIELD),rng.randrange(FIELD)) for _ in range(256)]
        a=cp.asarray([limbs(x) for x,y in pairs],dtype=np.uint32)
        b=cp.asarray([limbs(y) for x,y in pairs],dtype=np.uint32)
        out=cp.empty((len(pairs),24),dtype=np.uint32)
        self.arithmetic(((len(pairs)+self.threads-1)//self.threads,),(self.threads,),
                        (a,b,out,np.int32(len(pairs))))
        for (x,y),row in zip(pairs,out.get()):
            got=[integer(row[i:i+8]) for i in (0,8,16)]
            if got != [(x+y)%FIELD,(x-y)%FIELD,x*y%FIELD]:
                raise RuntimeError('GPU self-test: incorrect field arithmetic')
        starts=[2,ORDER-200]+[2**139+1000*i+123 for i in range(32)]
        target=point(starts[2]+7)
        state=cp.asarray([initial(k,self.ih) for k in starts],dtype=np.uint32)
        limits=np.array([32]*len(starts),dtype=np.uint32)
        hits,done=self.launch(state,limits,self.constants(target))
        host=state.get()
        for i,k in enumerate(starts):
            expected_hit=7 if i==2 else -1
            count=8 if i==2 else 32
            if int(hits[i])!=expected_hit or int(done[i])!=count:
                raise RuntimeError('GPU self-test: incorrect counter/match')
            self.check_state(host[i],k+count)
        # Resuming chains after a match, including no skipped candidates.
        hits2,done2=self.launch(state,np.array([5]*len(starts),dtype=np.uint32),self.constants(target))
        host=state.get()
        if any(int(v)!=-1 for v in hits2) or any(int(v)!=5 for v in done2):
            raise RuntimeError('GPU self-test: incorrect chain continuation')
        for i,k in enumerate(starts):
            self.check_state(host[i],k+int(done[i])+5)
        # Z=0 must not be counted as a verified candidate.
        bad=cp.zeros((1,32),dtype=np.uint32)
        hits,done=self.launch(bad,np.array([1],dtype=np.uint32),self.constants(target))
        if int(hits[0])!=-2 or int(done[0])!=0:
            raise RuntimeError('GPU self-test: exceptional state')
        print(f'GPU self-test OK: {len(pairs)} number pairs, {len(starts)} chains, continuation and Z=0.',flush=True)

    def check_state(self,row,k):
        for offset,scalar in [(0,k-1),(16,k)]:
            x,z=integer(row[offset:offset+8]),integer(row[offset+8:offset+16])
            if z==0 or self.h*x*pow(z,-1,FIELD)%FIELD != point(scalar)[0]:
                raise RuntimeError('GPU: control coordinate did not match CPU; search stopped')


def save_result(k,target,path):
    if point(k)!=target:
        raise RuntimeError('Final key failed independent verification')
    result=f'k_hex={k:064x}\nk_dec={k}\nP={encode(target)}\n'
    print('\nFOUND:\n'+result,end='')
    with Path(path).expanduser().open('a',encoding='utf-8') as stream:
        stream.write(result+'\n')
    print(f'Appended to {Path(path).expanduser().resolve()}')


def search(engine,start,end,target,args):
    cp,np=engine.cp,engine.np
    total=end-start+1
    checked=0
    # Exceptional ±G are checked on CPU; the interior stays a pure GPU chain.
    for k in (1,ORDER-1):
        if start<=k<=end:
            checked+=1
            if point(k)==target:
                args._found=k
                save_result(k,target,args.output)
                return 0
    lo,hi=max(start,2),min(end,ORDER-2)
    if lo>hi:
        print('Range checked. No matches.')
        return 0
    lanes=min(args.lanes,hi-lo+1)
    pieces=list(partitions(lo,hi,lanes))
    positions=[a for a,b in pieces]
    ends=[b for a,b in pieces]
    print(f'Preparing {lanes} initial chains on CPU...',flush=True)
    prep=time.perf_counter()
    host=np.empty((lanes,32),dtype=np.uint32)
    for i,k in enumerate(positions):
        host[i]=initial(k,engine.ih)
        if (i+1)%512==0:
            print(f'\rInitial chains: {i+1}/{lanes}',end='',flush=True)
    state=cp.asarray(host)
    constants=engine.constants(target)
    cp.cuda.get_current_stream().synchronize()
    print(f'\nPreparation: {time.perf_counter()-prep:.3f} s. Starting GPU search.',flush=True)
    begun=last_print=last_verify=time.perf_counter()
    searched=0
    advance=0
    min_remaining=min(b-k+1 for k,b in zip(positions,ends))
    max_remaining=max(b-k+1 for k,b in zip(positions,ends))
    full_limits=np.full(lanes,args.steps,dtype=np.uint32)
    while max_remaining>0:
        if min_remaining>=args.steps:
            limits=full_limits
        else:
            limits=np.array([min(args.steps,max(0,b-k-advance+1)) for k,b in zip(positions,ends)],dtype=np.uint32)
        hits,done=engine.launch(state,limits,constants)
        if np.any(done<0) or np.any(done>limits):
            raise RuntimeError('GPU: invalid counter')
        processed=int(done.sum(dtype=np.uint64))
        checked+=processed;searched+=processed
        if np.all(hits==-1):
            if not np.array_equal(done,limits):
                raise RuntimeError('GPU: not all candidates were verified')
            advance+=args.steps
            min_remaining-=args.steps
            max_remaining-=args.steps
        else:
            # Rare matches/exceptional states need individual lane positions.
            for i in range(lanes):
                old=min(positions[i]+advance,ends[i]+1)
                count=int(done[i]);hit=int(hits[i])
                positions[i]=old+count
                if hit>=0:
                    if count!=hit+1:
                        raise RuntimeError('GPU: invalid match offset')
                    k=old+hit
                    if point(k)==target:
                        elapsed=time.perf_counter()-begun
                        print(f'\nGPU search: {searched:,} candidates in {elapsed:.3f} s; {searched/elapsed:,.0f} cand./s')
                        args._found=k
                        print(progress_text(args,checked))
                        save_result(k,target,args.output)
                        return 0
                elif hit==-2 and positions[i]<=ends[i]:
                    state[i]=cp.asarray(initial(positions[i],engine.ih),dtype=np.uint32)
                elif hit!=-1 or count!=int(limits[i]):
                    raise RuntimeError('GPU: unexpected chain state')
            advance=0
            min_remaining=min(b-k+1 for k,b in zip(positions,ends))
            max_remaining=max(b-k+1 for k,b in zip(positions,ends))
        now=time.perf_counter()
        if now-last_verify>=10:
            # Periodic independent verification of the current coordinate of one chain.
            index=next((i for i,k in enumerate(positions) if k+advance<=ends[i]),None)
            if index is not None:
                engine.check_state(state[index].get(),positions[index]+advance)
            last_verify=now
        if now-last_print>=0.5:
            print('\r'+progress_text(args,checked)+'       ',end='',flush=True)
            last_print=now
    elapsed=time.perf_counter()-begun
    if checked!=total:
        raise RuntimeError('Not the entire range was verified')
    print(f'\nRange verified, no matches. Speed: {searched/elapsed:,.0f} cand./s')
    print('The segment speed above excludes preparation; the overall speed below includes it.')
    return 0


def scheduled_ranges(start,end,mode,block_bits,rng):
    """No-repeat coverage within a single run; no list of all blocks is stored."""
    if mode=='sequential':
        yield start,end
    elif mode=='random-start':
        pivot=rng.randrange(start,end+1)
        yield pivot,end
        if pivot>start:
            yield start,pivot-1
    else:
        width=1<<block_bits
        count=(end-start+width)//width
        offset=rng.randrange(count)
        stride=1
        if count>1:
            stride=rng.randrange(1,count)
            while math.gcd(stride,count)!=1:
                stride=rng.randrange(1,count)
        # This is a random shift and a coprime stride over block numbers,
        # not a uniformly random permutation of all possible orderings.
        for i in range(count):
            index=(offset+i*stride)%count
            lo=start+index*width
            yield lo,min(end,lo+width-1)


def progress_text(args,local_checked):
    stats=args._stats
    count=stats['completed']+local_checked
    elapsed=time.perf_counter()-stats['begun']
    rate=count/elapsed if elapsed else 0
    eta=(stats['total']-count)/rate/3600 if rate else float('inf')
    return (f"Verified {count:,}/{stats['total']:,} ({100*count/stats['total']:.6f}%) | "
            f"{rate:,.0f} cand./s | ETA for the whole range {eta:.2f} h")


def autotune(engine,args):
    """Tests identical chains on synthetic keys, not part of the search.
    Timing includes synchronization and CPU transfers; it excludes initial preparation.
    Only threads/steps are varied; the number of lanes stays as set by the user.
    """
    cp,np=engine.cp,engine.np
    lanes=args.lanes
    print(f'Auto-tuning threads/steps for {lanes} chains. Preparing...',flush=True)
    starts=[2**139+100000000*i+12345 for i in range(lanes)]
    host=np.asarray([initial(k,engine.ih) for k in starts],dtype=np.uint32)
    state=cp.asarray(host)
    constants=engine.constants(point(1))
    configs=[(threads,steps) for threads in (64,128,256) for steps in (32,128,256)]
    scores={config:[] for config in configs}
    for trial in range(3):
        for threads,steps in (configs if trial%2==0 else configs[::-1]):
            engine.threads=threads
            state.set(host)
            limits=np.full(lanes,steps,dtype=np.uint32)
            hits,done=engine.launch(state,limits,constants)
            if np.any(hits!=-1) or np.any(done!=steps):
                raise RuntimeError('Autotune control launch error')
            elapsed=0.0
            iterations=0
            begun=time.perf_counter()
            while elapsed<0.15:
                hits,done=engine.launch(state,limits,constants)
                if np.any(hits!=-1) or np.any(done!=steps):
                    raise RuntimeError('Autotune counter error')
                iterations+=1
                elapsed=time.perf_counter()-begun
            # A few chain endpoints are verified independently outside the timer.
            for index in sorted(set([0,lanes//2,lanes-1])):
                engine.check_state(state[index].get(),starts[index]+(iterations+1)*steps)
            scores[(threads,steps)].append(lanes*steps*iterations/elapsed)
    medians={config:statistics.median(values) for config,values in scores.items()}
    for (threads,steps),rate in sorted(medians.items(),key=lambda item:item[1],reverse=True):
        print(f'  threads={threads:3d} steps={steps:3d}: {rate:,.0f} cand./s')
    args.threads,args.steps=max(medians,key=medians.get)
    engine.threads=args.threads
    print(f'Selected: --lanes {args.lanes} --threads {args.threads} --steps {args.steps}',flush=True)
    print('This is a short test; long-run speed also depends on GPU heating and clock rates.')


def search_modes(engine,start,end,target,args):
    seed=args.seed if args.seed is not None else secrets.randbits(64)
    rng=random.Random(seed)
    print(f'Mode: {args.mode}; seed: {seed}')
    print('The speed below includes preparation and segment switching; progress is global.')
    if args.mode=='random':
        print(f'Segment size: 2^{args.block_bits} keys. Segments do not repeat within a single run.')
    args._stats={'begun':time.perf_counter(),'completed':0,'total':end-start+1}
    args._found=None
    for number,(lo,hi) in enumerate(scheduled_ranges(start,end,args.mode,args.block_bits,rng),1):
        print(f'\nSegment {number}: {lo:x}:{hi:x}',flush=True)
        result=search(engine,lo,hi,target,args)
        if args._found is not None or result!=0:
            return result
        args._stats['completed']+=hi-lo+1
        print(progress_text(args,0),flush=True)
    if args._stats['completed']!=end-start+1:
        raise RuntimeError('Full range coverage error')
    print('The entire given range was verified without repeats. No matches.')
    return 0


def main():
    parser=argparse.ArgumentParser(description=__doc__,formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--start',help='Start in HEX, inclusive')
    parser.add_argument('--end',help='End in HEX, inclusive')
    parser.add_argument('--pubkey',help='SEC1 public key in HEX')
    parser.add_argument('--gpu',type=int,default=0,help='NVIDIA GPU number')
    parser.add_argument('--lanes',type=int,default=1024,help='Independent GPU chains, default 1024')
    parser.add_argument('--threads',type=int,choices=[32,64,128,256],default=128,help='CUDA threads per block')
    parser.add_argument('--steps',type=int,default=32,help='Steps per chain per CUDA launch, 1..256')
    parser.add_argument('--mode',choices=['sequential','random-start','random'],default='sequential',help='Order of segment verification')
    parser.add_argument('--seed',type=int,help='Seed for a reproducible ordering; without it every run is new')
    parser.add_argument('--block-bits',type=int,default=36,help='random: segment size 2^N keys, default N=36')
    parser.add_argument('--autotune',action='store_true',help='Tune threads/steps on the GPU before searching')
    parser.add_argument('--self-test',action='store_true',help='GPU verification only, no search')
    parser.add_argument('--output',default='found_gpu.txt',help='Result file, append mode')
    args=parser.parse_args()
    if not 1<=args.block_bits<=256:
        parser.error('Need 1 <= block-bits <= 256')
    if not 1<=args.lanes<=65536 or not 1<=args.steps<=256:
        parser.error('Need 1 <= lanes <= 65536 and 1 <= steps <= 256')
    try:
        if not args.self_test:
            start=parse_hex(args.start if args.start is not None else input('Start HEX: '))
            end=parse_hex(args.end if args.end is not None else input('End HEX (inclusive): '))
            target=parse_point(args.pubkey if args.pubkey is not None else input('Public key P: '))
            if not 1<=start<=end<ORDER:
                raise ValueError('Need 1 <= start <= end <= n-1')
        engine=Engine(args.gpu,args.threads)
        print(f'GPU: {engine.name}. 8x32 arithmetic. Compiling CUDA and running mandatory self-test...',flush=True)
        engine.self_test()
        if args.self_test:
            return 0
        if args.autotune:
            autotune(engine,args)
        print(f'HEX: {start:x}:{end:x}; P: {encode(target)}')
        print('Ctrl+C: stops between GPU launches, without saving the position.')
        return search_modes(engine,start,end,target,args)
    except ImportError as exc:
        print(f'Missing dependency: {exc}\nInstall with: python -m pip install "cupy-cuda12x[ctk]" cryptography',file=sys.stderr)
        return 1
    except UnicodeError as exc:
        print(f'Encoding error: {exc}. Try: python -X utf8 xz_gpu32.py --self-test',file=sys.stderr)
        return 1
    except (ValueError,EOFError) as exc:
        parser.error(str(exc))
    except Exception as exc:
        print(f'\nERROR: {type(exc).__name__}: {exc}\nSearch completeness is not confirmed.',file=sys.stderr)
        return 1


if __name__=='__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print('\nStopped by the user. The range was not fully verified.')
        sys.exit(130)
