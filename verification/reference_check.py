#!/usr/bin/env python3
# Independent reference for hkf_selftest.c. Recomputes every value from scratch and prints it in the
# same format; diff the two outputs -- they must be identical.
import hmac, hashlib
def h(label,b): print(f"{label} "+b.hex())
tab=[]
for n in range(256):
    c=n
    for _ in range(8): c=(0xEDB88320^(c>>1)) if (c&1) else (c>>1)
    tab.append(c)
def mix(password,response,POOL=128):
    pool=[0]*POOL; crc=0xffffffff; wp=0
    for byte in response:
        crc=tab[(crc^byte)&0xff]^(crc>>8)
        for sh in (24,16,8,0):
            pool[wp]=(pool[wp]+((crc>>sh)&0xff))&0xff; wp=(wp+1)%POOL
    pw=bytearray(password)+bytes(max(0,POOL-len(password)))
    for i in range(POOL): pw[i]=(pw[i]+pool[i])&0xff if i<len(password) else pool[i]
    return bytes(pw)
# 1
h("hmac_sha1_rfc2202 =",hmac.new(b"\x0b"*20,b"Hi There",hashlib.sha1).digest())
# 2
salt=bytes(((i*7+1)&0xff) for i in range(64)); secret=bytes(range(1,21))
resp=hmac.new(secret,salt,hashlib.sha1).digest(); h("yk_response       =",resp)
# 3
mixed=mix(b"correct horse battery staple",resp); print("mixed_len         = 128"); h("mixed_pw32        =",mixed[:32])
# 4
cred=bytes(0xA0+i for i in range(32)); salt32=hashlib.sha256(salt).digest()
h("fido2_response    =",hmac.new(cred,salt32,hashlib.sha256).digest())
