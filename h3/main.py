from typing import List, Union
import binascii

class SM3:
    
    def __init__(self, debug=False) -> None:
        self.IV = tuple([
            0x7380166f, 
            0x4914b2b9, 
            0x172442d7, 
            0xda8a0600,
            0xa96f30bc, 
            0x163138aa, 
            0xe38dee4d, 
            0xb0fb0e4e
        ])
        self.debug = debug
        self.hash_l = 512 // 8
        
    def T(self, index):
        if index<=15:
            return 0x79cc4519
        return 0x7a879d8a
    
    def FF(self, X: int,Y: int,Z: int, index):
        if index<=15:
            return X^Y^Z
        return (X & Y) | (X & Z) | (Y & Z)
    
    def GG(self, X: int, Y: int, Z: int, index):
        if index<=15:
            return X ^ Y ^ Z
        return (X & Y) | ( (0xFFFFFFFF - X) & Z)
    
    def ROTWord(self, X: int, shift:int):
        return (X >> (32 - shift)) + ((X & ((1<< (32 - shift)) - 1)) << shift)
    
    def P0(self, X:int):
        return X ^ self.ROTWord(X, 9) ^ self.ROTWord(X, 17)
    
    def P1(self, X:int):
        return X ^ self.ROTWord(X, 15) ^ self.ROTWord(X, 23)
    
    def byte2word(self, *bytes: List[int])->int:
        return (bytes[0] << 24) + (bytes[1] << 16) + (bytes[2] << 8) + bytes[3]
    
    def groups(self, m: bytearray)->List[List[int]]:
        gs = []
        for i in range(0, len(m),64):
            g = []
            for j in range(0, 64, 4):
                g.append(
                    self.byte2word(m[i + j], m[i + j + 1], m[i + j + 2], m[i + j + 3])
                )
            gs.append(g)
        return gs
        
    def pad(self, m: bytearray):
        l = len(m)
        if (l + 8) % 64 !=0:
            m.append(0x80)
        while (len(m) + 8) % 64 != 0: 
            m.append(0x00)
        for i in range(8):
            m.append((l * 8) >> (56 - i * 8) & 0xFF)
        return m        
    
    def w(self, m: List[int]):
        w = m[:]
        for j in range(16, 68):
            w.append(
                self.P1(w[j-16] ^ w[j-9] ^ self.ROTWord(w[j-3], 15))
                ^ self.ROTWord(w[j-13], 7) ^ w[j-6]
            )
        for j in range(64):
            w.append(w[j] ^ w[j+4])
        return w
            
    def mod(self, x):
        return x & ((1<<32) - 1)
    
    def add(self, x, y):
        return self.mod(x + y)
            
    def compress(self, v, w):
        a,b,c,d,e,f,g,h = v
        if self.debug:
            print(f"   {hex(a)[2:].zfill(8):10} {hex(b)[2:].zfill(8):10} {hex(c)[2:].zfill(8):10} {hex(d)[2:].zfill(8):10} {hex(e)[2:].zfill(8):10} {hex(f)[2:].zfill(8):10} {hex(g)[2:].zfill(8):10} {hex(h)[2:].zfill(8):10}")
        for j in range(64):
            ss1 = self.ROTWord(self.add(self.add(self.ROTWord(a, 12), e), self.ROTWord(self.T(j), j % 32)), 7)
            ss2 = ss1 ^ self.ROTWord(a, 12)
            tt1 = self.add(self.add(self.add(self.FF(a,b,c,j),d), ss2),w[j+68])
            tt2 = self.add(self.add(self.add(self.GG(e,f,g,j),h),ss1),w[j])
            d = c
            c = self.ROTWord(b, 9)
            b = a
            a = tt1
            h = g
            g = self.ROTWord(f, 19)
            f = e
            e = self.P0(tt2)
            if self.debug:
                print(f"{j:2} {hex(a)[2:].zfill(8):10} {hex(b)[2:].zfill(8):10} {hex(c)[2:].zfill(8):10} {hex(d)[2:].zfill(8):10} {hex(e)[2:].zfill(8):10} {hex(f)[2:].zfill(8):10} {hex(g)[2:].zfill(8):10} {hex(h)[2:].zfill(8):10}")
        return tuple([
            a ^ v[0],
            b ^ v[1],
            c ^ v[2],
            d ^ v[3],
            e ^ v[4],
            f ^ v[5],
            g ^ v[6],
            h ^ v[7]
        ])
        
    def digest(self, m: Union[str, bytearray], encoding="ascii"):
        if isinstance(m, str):
            m = bytearray(m, encoding)
        else:
            m = bytearray(m)
        m = self.pad(m)
        groups = self.groups(m)
        v = self.IV
        for group in groups:
            w = self.w(group)
            v = self.compress(v, w)
        return self.word2bytes(v)
    
    def word2bytes(self, words: List[int])->bytearray:
        a = bytearray()
        for word in words:
            # word 32 bit
            a.append(word >> 24 & 0xFF)
            a.append(word >> 16 & 0xFF)
            a.append(word >> 8 & 0xFF)
            a.append(word & 0xFF)
        return a  
    
    def echoGroups(self, m: list[list[int]], width: int = 8):
        def flattern(m):
            if isinstance(m, list):
                r = []
                for i in m:
                    i = flattern(i)
                    if isinstance(i, list):
                        r += i
                    else:
                        r.append(i)
                return r
            return m
        m = flattern(m)
        for i in range(0, len(m),width):
            for word in m[i : i + width]:
                print(f"{hex(word)[2:].zfill(8):10}", end='')
            print()
            
class HashWrap():
    
    def __init__(self, callable, hash_l) -> None:
        self.callable = callable
        self.hash_l = hash_l
        
    def digest(self, m):
        return self.callable(m)
            
class HMAC():
    
    def __init__(self, key: Union[str, bytearray], hash=SM3(), encoding="ascii", debug = True, hash_l = None) -> None:
        if hash_l is None:
            hash_l = hash.hash_l
        self.hash = hash
        if isinstance(key, str):
            key = bytearray(key, encoding=encoding)
        key = bytearray(key)
        self.key = key + bytearray([0x00] * max(0, hash_l - len(key)))
        if len(self.key) > hash.hash_l:
            self.key = hash.digest(self.key)
        self.ipad = bytearray([0x36] * hash_l )
        self.opad = bytearray([0x5c] * hash_l )
        self.ipadkey = self.xor(self.key, self.ipad)
        self.opadkey = self.xor(self.key, self.opad)
        self.debug = debug
        if self.debug:
            print(f"key    ={binascii.hexlify(self.key)}")
            print(f"ipad   ={binascii.hexlify(self.ipad)}")
            print(f"ipadkey={binascii.hexlify(self.ipadkey)}")
            print(f"opad   ={binascii.hexlify( self.opad)}")
            print(f"ipadkey={binascii.hexlify(self.opadkey)}")
            
        
    def xor(self, a: bytearray, b: bytearray):
        return bytearray(a[i] ^ b[i] for i in range(len(a)))
        
    def digest(self, plain: Union[str, bytearray], encoding="ascii"):
        if isinstance(plain, str):
            plain = bytearray(plain, encoding=encoding)
        plain = bytearray(plain)
        if self.debug:
            print(f"       ={binascii.hexlify(plain)}")
        t = bytearray(self.ipadkey + plain)
        if self.debug:
            print(f"       ={binascii.hexlify(t)}")
        t = bytearray(self.hash.digest(t))
        if self.debug:
            print(f"       ={binascii.hexlify(t)}")
        t = bytearray(self.opadkey + t)
        if self.debug:
            print(f"       ={binascii.hexlify(t)}")
        return self.hash.digest(t)
    
if __name__=='__main__':
    sm3 = SM3()
    m = bytearray("123", encoding="ascii") 
    
    hmac = HMAC("123",sm3)
    digest = hmac.digest(m)
    # https://www.lddgo.net/en/encrypt/hmac
    # 正确的值 65f2d88b32114f3c7b22a41585e85035249aefad3ba08d51d0bb95ac2204c814
    print(binascii.hexlify(digest))
    
        
        