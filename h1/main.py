from typing import List,Union

class Crypto():
    
    def encrypt(self, plain: Union[int,List[int]])->Union[int, List[int]]:
        pass
    
    def decrypt(self, ciphter: Union[int,List[int]])->Union[int, List[int]]:
        pass

class AES(Crypto):
    
    def __init__(self, key, debug=False) -> None:
        self.sBox = [
            [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76],
            [0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0],
            [0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15],
            [0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75],
            [0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84],
            [0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF],
            [0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8],
            [0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2],
            [0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73],
            [0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB],
            [0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79],
            [0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08],
            [0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A],
            [0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E],
            [0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF],
            [0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]
        ]
        self.sBoxInv = [
            [0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB],
            [0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB],
            [0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E],
            [0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25],
            [0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92],
            [0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84],
            [0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06],
            [0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B],
            [0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73],
            [0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E],
            [0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B],
            [0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4],
            [0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F],
            [0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF],
            [0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61],
            [0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D]
        ]
        self.rCon = [
            0x01000000, 
            0x02000000, 
            0x04000000, 
            0x08000000, 
            0x10000000, 
            0x20000000, 
            0x40000000, 
            0x80000000, 
            0x1B000000, 
            0x36000000
        ]
        self.mixC = [
            0x2, 0x3, 0x1, 0x1, 
            0x1, 0x2, 0x3, 0x1, 
            0x1, 0x1, 0x2, 0x3, 
            0x3, 0x1, 0x1, 0x2
        ]
        self.mixCInv = [
            0xe, 0xb, 0xd, 0x9, 
            0x9, 0xe, 0xb, 0xd, 
            0xd, 0x9, 0xe, 0xb, 
            0xb, 0xd, 0x9, 0xe
        ]
        self.key = key
        self.roundKeys = self.roundKeyGenerator(self.key)
        self.debug = debug
        
    def ROTL1(self, bytes:int) -> int:
        """
        将第一个八位放到末尾, bytes: 32 bit
        """
        return ((bytes & 0xFFFFFFFF) << 8) + (bytes >> 24)
        
    def roundKeyGenerator(self, bytes: int):
        """
        轮密钥生成, bytes: 128 bit
        """
        w = [
            bytes >> 96,
            bytes >> 64 & 0xFFFFFFFF,
            bytes >> 32 & 0xFFFFFFFF,
            bytes & 0xFFFFFFFF
        ] + [0] * 40
        for i in range(4, 44):
            t = w[i-1]
            if i % 4==0:
                t = self.subByte(self.ROTL1(t)) ^ self.rCon[i//4-1]
            w[i] = w[i-4] ^ t
        # 合并密钥
        return [sum([w[4 * i] << 96, w[4*i+1] << 64, 
                        w[4*i+2] << 32, w[4*i+3]]) for i in range(11)]
        
    def subByte(self, byte: int):
        """
        bytes: 32 bit
        """
        result = 0
        for position in range(4):
            i = byte >> (position * 8 + 4) & 0xF
            j = byte >> (position * 8) & 0xF
            result ^= self.sBox[i][j] << (position * 8)
        return result
    
    def subByteInv(self, byte: int):
        result = 0
        for position in range(4):
            i = byte >> (position * 8 + 4) & 0xF
            j = byte >> (position * 8) & 0xF
            result ^= self.sBoxInv[i][j] << (position * 8)
        return result
    
    def addRoundKey(self, state:int, key:int )->int:
        """
        state: 128 bit
        key: 128 bit
        """
        return state ^ key
    
    def subBytes(self, state: int)->int:
        # state状态总共128位，其中每4位为一组，共32个
        result = 0
        for i in range(0,128,32):
            byte = state >> i & 0xFFFFFFFF
            result ^= self.subByte(byte) << i
        return result
    
    def subBytesInv(self, state: int)->int:
        # state状态总共128位，其中每4位为一组，共32个
        result = 0
        for i in range(0,128,32):
            byte = state >> i & 0xFFFFFFFF
            result ^= self.subByteInv(byte) << i
        return result
    
    def shiftRows(self, state: int):
        state = self.bytes2list(state)
        return self.list2bytes([
                state[ 0], state[ 5], state[10], state[15], 
                state[ 4], state[ 9], state[14], state[ 3],
                state[ 8], state[13], state[ 2], state[ 7],
                state[12], state[ 1], state[ 6], state[11]
            ])
        
    def shiftRowsInv(self, state):
        state = self.bytes2list(state)
        return self.list2bytes([
                state[ 0], state[13], state[10], state[ 7],
                state[ 4], state[ 1], state[14], state[11],
                state[ 8], state[ 5], state[ 2], state[15],
                state[12], state[ 9], state[ 6], state[ 3]
            ])
    
    def mul(self, a: int, b: int):
        result = 0
        for index in range(b.bit_length()):
            if b & 1 << index:
                result ^= a << index
        return result
    
    def mod(self, a:int, mod = 0b100011011):
        while a.bit_length()>8:
            a^= mod << a.bit_length() - 9
        return a
                
    def matrixMul(self, a, b):
        b = self.bytes2list(b)
        result = [0] * 16
        for row in range(4):
            for col in range(4):
                for round in range(4):
                    result[row + col*4] ^= self.mul(a[row*4+round],b[round+col*4])
                result[row+col*4] = self.mod(result[row+col*4])
        result = self.list2bytes(result)
        return result
    
    def mixColumns(self, state):
        return self.matrixMul(self.mixC, state)
    
    def mixColumnsInv(self, state):
        return self.matrixMul(self.mixCInv, state)
    
    def bytes2list(self, state:int):
        r = []
        for i in range(0,128,8):
            r.append(state >> (120-i) & 0xFF)
        return r
    
    def list2bytes(self, state: List[int]):
        r = 0
        for i in range(len(state)):
            r ^= (state[i] << (120 - i * 8))
        return r
    
    def echo(self, state:int):
        if self.debug:
            state = self.bytes2list(state)
            print(f"{hex(state[0])[2:]} {hex(state[4])[2:]} {hex(state[8])[2:]} {hex(state[12])[2:]}")
            print(f"{hex(state[1])[2:]} {hex(state[5])[2:]} {hex(state[9])[2:]} {hex(state[13])[2:]}")
            print(f"{hex(state[2])[2:]} {hex(state[6])[2:]} {hex(state[10])[2:]} {hex(state[14])[2:]}")
            print(f"{hex(state[3])[2:]} {hex(state[7])[2:]} {hex(state[11])[2:]} {hex(state[15])[2:]}")
        
    def echo_round(self, round, key, v):
        if self.debug:
            print(f"round[{round:2}].{key} \t {hex(v)[2:].zfill(32)}")
        
    def encrypt(self, plain: int):
        if self.debug:
            print("CIPHER (ENCRYPT): ")
        state = plain
        self.echo_round(0, "input", state)
        self.echo_round(0, "k_sch", self.roundKeys[0])
        state = self.addRoundKey(state, self.roundKeys[0])
       
        for round in range(1, 11):
            self.echo_round(round, "start", state)
            state = self.subBytes(state) 
            self.echo_round(round, "s_box", state)
            state = self.shiftRows(state)
            self.echo_round(round,"s_row", state)
            if round<10:
                state = self.mixColumns(state) 
            self.echo_round(round, "m_col", state)
            state = self.addRoundKey(state, self.roundKeys[round])
            self.echo_round(round, "k_sch", self.roundKeys[round])
        self.echo_round(10, "output", state)
        return state
    
    def decrypt(self, clip: int):
        if self.debug:
            print("INVERSE CIPHER (DECRYPT):")
        state = clip
        self.echo_round(0, "iinput", state)
        self.echo_round(0, "ik_sch", self.roundKeys[-1])
        state = self.addRoundKey(state, self.roundKeys[-1])
        for round in range(1,11):
            self.echo_round(round, "istart", state)
            state = self.shiftRowsInv(state)
            self.echo_round(round,"is_row", state)
            state = self.subBytesInv(state)    
            self.echo_round(round, "is_box", state)  
            state = self.addRoundKey(state, self.roundKeys[-1-round])
            self.echo_round(round, "ik_sch", self.roundKeys[-1-round])
            if round<10:
                state = self.mixColumnsInv(state)  
                self.echo_round(round, "im_col", state)
        self.echo_round(10, "ioutput", state)
        return state
    
class CBC(Crypto):
    
    def __init__(self, crypto: Crypto, IV = 0x000102030405060708090a0b0c0d0e0f) -> None:
        self.crypto = crypto
        self.IV = IV
        
    def encrypt(self, blocks:List[int]):
        ciphers = []
        p = self.IV
        for block in blocks:
            p = self.crypto.encrypt(block ^ p)
            ciphers.append(p)
        return ciphers
    
    def decrypt(self, blocks:List[int]):
        plains = []
        p = self.IV
        for block in blocks:
            plains.append(p ^ self.crypto.decrypt(block))
            p = block
        return plains
    
class CFB(Crypto):
    
    def __init__(self, crypto: Crypto, IV = 0x000102030405060708090a0b0c0d0e0f) -> None:
        self.crypto = crypto
        self.IV = IV
        
    def encrypt(self, blocks:List[int]):
        ciphers = []
        p = self.IV
        for block in blocks:
            p = block ^ self.crypto.encrypt(p)
            ciphers.append(p)
        return ciphers
    
    def decrypt(self, blocks:List[int]):
        plains = []
        p = self.IV
        for block in blocks:
            plains.append(block ^ self.crypto.encrypt(p))
            p = block
        return plains
    
def hexexpr(state):
    if isinstance(state, list):
        return str(list(hexexpr(i) for i in state))
    return hex(state)[2:].zfill(32)
                
if __name__=="__main__":
    key = 0x000102030405060708090a0b0c0d0e0f
    plaintext = 0x00112233445566778899aabbccddeeff
    task = 2
    if task==1:
        aes = AES(key,debug=True)
        c = aes.encrypt(plaintext)
        aes.decrypt(c)
    elif task==2:
        aes = AES(key,debug=False)
        cbc = CBC(aes)
        m = [plaintext, key]
        print(hexexpr(m))
        c = cbc.encrypt(m)
        print(hexexpr(c))
        print(hexexpr(cbc.decrypt(c)))
    elif task==3:
        aes = AES(key,debug=False)
        cfb = CFB(aes)
        m = [plaintext, key]
        print(hexexpr(m))
        c = cfb.encrypt(m)
        print(hexexpr(c))
        print(hexexpr(cfb.decrypt(c)))