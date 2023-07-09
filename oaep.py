import hashlib
import math
import random
import os

def i2osp(x: int, xlen: int) -> bytes:
    '''Converte um inteiro positivo para uma string de tamanho definido'''
    return x.to_bytes(xlen, byteorder='big')

def mgf1(seed: bytes, mlen: int, f_hash = hashlib.sha3_256) -> bytes:
    '''MGF1 mask'''
    t = b''
    hlen = len(f_hash(b'').digest())
    for c in range(0, math.ceil(mlen / hlen)):
        _c = i2osp(c, 4)
        t += f_hash(seed + _c).digest()
    return t[:mlen]

def xor(data: bytes, mask: bytes) -> bytes:
    '''bitwise xor em dois arrays'''
    masked = b''
    ldata = len(data)
    lmask = len(mask)
    for i in range(max(ldata, lmask)):
        if i < ldata and i < lmask:
            masked += (data[i] ^ mask[i]).to_bytes(1, byteorder='big')
        elif i < ldata:
            masked += data[i].to_bytes(1, byteorder='big')
        else:
            break
    return masked

def oaep_encode(m: bytes, k: int, label: bytes = b'',
                f_hash = hashlib.sha3_256, f_mgf = mgf1) -> bytes:
    mlen = len(m)
    lhash = f_hash(label).digest()
    hlen = len(lhash)
    ps = b'\x00' * (k - mlen - 2 * hlen - 2)
    db = lhash + ps + b'\x01' + m
    seed = os.urandom(hlen)
    db_mask = f_mgf(seed, k - hlen - 1, f_hash)
    masked_db = xor(db, db_mask)
    seed_mask = f_mgf(masked_db, hlen, f_hash)
    masked_seed = xor(seed, seed_mask)
    return b'\x00' + masked_seed + masked_db

def oaep_decode(c: bytes, k: int, label: bytes = b'',
                f_hash = hashlib.sha3_256, f_mgf = mgf1) -> bytes:
    clen = len(c)
    lhash = f_hash(label).digest()
    hlen = len(lhash)
    _, masked_seed, masked_db = c[:1], c[1:1 + hlen], c[1 + hlen:]
    seed_mask = f_mgf(masked_db, hlen, f_hash)
    seed = xor(masked_seed, seed_mask)
    db_mask = f_mgf(seed, k - hlen - 1, f_hash)
    db = xor(masked_db, db_mask)
    _lhash = db[:hlen]
    assert lhash == _lhash
    i = hlen
    while i < len(db):
        if db[i] == 0:
            i += 1
            continue
        elif db[i] == 1:
            i += 1
            break
        else:
            raise Exception()
    m = db[i:]
    return m

if __name__ == "__main__":
    a = oaep_encode(bytes(input().encode()), 1024%-41)
    print(a)
    print(oaep_decode(a, 1024%-41))


# class OAEP:
#     def __init__(self, algorithm, mask):
#         self.algorithm = algorithm
#         self.mask = mask

#     def padder(self, message: str):
#         x = (message)