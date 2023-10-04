from typing import List

class AES():
    
    def __init__(self) -> None:
        self.sBox = [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]
        self.sBoxInv = [
            0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB,0x3C, 0x83, 0x53, 0x99, 0x61,
0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
        ]
        self.rCon = [0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1B000000, 0x36000000]
        self.mixC = [0x2, 0x3, 0x1, 0x1 , 0x1, 0x2, 0x3, 0x1 , 0x1, 0x1, 0x2, 0x3, 0x3, 0x1, 0x1, 0x2]
        self.mixCInv = [0xe, 0xb, 0xd, 0x9, 0x9, 0xe, 0xb, 0xd, 0xd, 0x9, 0xe, 0xb, 0xb, 0xd, 0x9, 0xe]
        self.initVectorIV = self.num2hbyte(0x000102030405060708090a0b0c0d0e0f)
    
    def addRoundKey(self, state:List[int], extendKey:List[int], index)->'AES':
        for i in range(len(state)):
            state[i] ^= extendKey[index][i]
        return self
    
    def subWord(self, _4byte_block):
        result = 0
        for position in range(4):
            i = _4byte_block >> position * 8 + 4 & 0xf
            j = _4byte_block >> position * 8 & 0xf
            result ^= self.sBox[(i<<4) + j] << position * 8
        return result
    
    def rotWord(self, _4byte_block):
        return ((_4byte_block & 0xffffff) << 8) + (_4byte_block >> 24)
    
    def subBytes(self, state:List[int])->'AES':
        # state状态总共128位，其中每4位为一组，共32个
        for i in range(0,len(state),2):
            a = self.sBox[(state[i]<<4)+state[i+1]]
            a,b = ((a>>4) & 0xf),(a&0xf)
            state[i] = a
            state[i+1] = b  
        return self
    
    def subBytesInv(self, state: List[int])->'AES':
        # state状态总共128位，其中每4位为一组，共32个
        for i in range(0,len(state),2):
            a = self.sBoxInv[(state[i]<<4)+state[i+1]]
            a,b = ((a>>4) & 0xf),(a&0xf)
            state[i] = a
            state[i+1] = b  
        return self
    
    def shiftRows(self, state):
        state = self.hbyte2byte(state)
        return self.byte2hbyte([state[ 0], state[ 5], state[10], state[15], 
                state[ 4], state[ 9], state[14], state[ 3],
                state[ 8], state[13], state[ 2], state[ 7],
                state[12], state[ 1], state[ 6], state[11]])
        
    def shiftRowsInv(self, state):
        state = self.hbyte2byte(state)
        return self.byte2hbyte([state[ 0], state[13], state[10], state[ 7],
                state[ 4], state[ 1], state[14], state[11],
                state[ 8], state[ 5], state[ 2], state[15],
                state[12], state[ 9], state[ 6], state[ 3]])
    
    def mul(self, a,b):
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
        b = self.hbyte2byte(b)
        result = [0] * 16
        for row in range(4):
            for col in range(4):
                for round in range(4):
                    result[row + col*4] ^= self.mul(a[row*4+round],b[round+col*4])
                result[row+col*4] = self.mod(result[row+col*4])
        result = self.byte2hbyte(result)
        return result
    
    def mixColumns(self, state):
        return self.matrixMul(self.mixC, state)
    
    def mixColumnsInv(self, state):
        return self.matrixMul(self.mixCInv, state)
    
    def roundKeyGenerator(self, _16bytes_key):
        w = [_16bytes_key >> 96, 
                _16bytes_key >> 64 & 0xFFFFFFFF, 
                _16bytes_key >> 32 & 0xFFFFFFFF, 
                _16bytes_key & 0xFFFFFFFF] + [0]*40
        for i in range(4, 44):
            temp = w[i-1]
            if not i % 4:
                temp = self.subWord(self.rotWord(temp)) ^ self.rCon[i//4-1]
            w[i] = w[i-4] ^ temp
        return [self.num2hbyte(sum([w[4 * i] << 96, w[4*i+1] << 64, 
                        w[4*i+2] << 32, w[4*i+3]]))
                     for i in range(11)]
        
    def num2hbyte(self, num):
        """
        数字转Byte数组

        Args:
            num (int): 数字

        Returns:
            List[int]: byte
        """
        result = [0] * 32
        i = 0
        while num>0:
            result[i] = num & 0x0f
            i+=1
            num>>=4
        result.reverse()
        return result
    
    def hbyte2byte(self, num:List[int]):
        new_num = []
        for i in range(0,len(num),2):
            new_num.append(num[i]*16+num[i+1])
        return new_num
    
    def byte2hbyte(self, num:List[int]):
        new_new = []
        for i in range(0, len(num)):
            new_new.append(num[i]>>4)
            new_new.append(num[i] & 0xf)
        return new_new
    
    def hbyte2num(self, num):
        """
        byte数组转数字

        Args:
            num (List[int]): 比特数组

        Returns:
            int: 数字
        """
        result = 0
        for i in num:
            result = result*16+i
        return result
    
    def echo(self, state):
        if isinstance(state[0], list):
            return list(self.echo(i) for i in state)
        state = self.hbyte2num(state)
        echo = f"0x{hex(state)[2:].zfill(32)}"
        return echo
        
    def encrypt(self, plaintext_list, roundKeys):
        state = plaintext_list[:]
        self.addRoundKey(state, roundKeys, 0)
        for round in range(1, 10):
            self.subBytes(state) 
            state = self.shiftRows(state)
            state = self.mixColumns(state) 
            self.addRoundKey(state, roundKeys, round)
        self.subBytes(state) 
        state = self.shiftRows(state) 
        self.addRoundKey(state, roundKeys, 10)
        return state
    
    def decrypt(self, ciphertext_list, roundKeys):
        state = ciphertext_list[:]
        self.addRoundKey(state, roundKeys, 10)
        for round in range(1,10):
            state = self.shiftRowsInv(state)
            self.subBytesInv(state)      
            self.addRoundKey(state, roundKeys, 10-round)
            state = self.mixColumnsInv(state)  
        state = self.shiftRowsInv(state)   
        self.subBytesInv(state)    
        self.addRoundKey(state, roundKeys, 0)
        return state
    
    def encryptBlocks(self, plainBlocks, key, mode ="CBC"):
        if mode=='CBC':
            cipherBlock = self.hbyte2num(self.initVectorIV)
            cipherBlocks = []
            roundKeys = aes.roundKeyGenerator(key)
            for block in plainBlocks:
                vec = cipherBlock^self.hbyte2num(block)
                vec = self.num2hbyte(vec)
                cipherBlock = self.encrypt(vec, roundKeys)
                cipherBlocks.append(cipherBlock)
                cipherBlock = self.hbyte2num(cipherBlock)
            return cipherBlocks
        elif mode=="CFB":
            cipherBlock = self.initVectorIV
            cipherBlocks = []
            roundKeys = aes.roundKeyGenerator(key)
            for block in plainBlocks:
                vec = self.encrypt(cipherBlock, roundKeys)
                cipherBlock = self.hbyte2num(block) ^ self.hbyte2num(vec)
                cipherBlock = self.num2hbyte(cipherBlock)
                cipherBlocks.append(cipherBlock)
            return cipherBlocks           
    
    def decryptBlocks(self, ciphterBlocks, key, mode="CBC"):
        if mode=="CBC":
            plainBlock = self.hbyte2num(self.initVectorIV)
            plainBlocks = []
            roundKeys = aes.roundKeyGenerator(key)
            for block in ciphterBlocks:
                vec = self.decrypt(block, roundKeys)
                plainBlock = self.hbyte2num(vec) ^ plainBlock
                plainBlocks.append(self.num2hbyte(plainBlock))
                plainBlock = self.hbyte2num(block)
            return plainBlocks
        elif mode=="CFB":
            plainBlock = self.initVectorIV
            plainBlocks = []
            roundKeys = aes.roundKeyGenerator(key)
            for block in ciphterBlocks:
                # CFB模式中，都是使用的加密而非解密
                vec = self.encrypt(plainBlock, roundKeys)
                plainBlock = block
                plainBlocks.append(self.num2hbyte(self.hbyte2num(vec) ^ self.hbyte2num(plainBlock)))
            return plainBlocks
                
if __name__=="__main__":
    aes = AES()
    plaintext = 0x00112233445566778899aabbccddeeff
    key = 0x000102030405060708090a0b0c0d0e0f
    plaintext_bytes = aes.num2hbyte(plaintext)
    origin = [plaintext_bytes[:], aes.num2hbyte(key)]
    mode = "CFB"
    blocks = aes.encryptBlocks(origin, key, mode)
    print(aes.echo(blocks))
    deblocks = aes.decryptBlocks(blocks, key, mode)
    print(aes.echo(deblocks))
    