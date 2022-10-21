from re import match
from math import ceil

class hash(object):
    def hash(self, msg):
        length = bin(len(msg) * 8)[2:].rjust(self.block, "0")      
        while len(msg) > self.block:            
            self.hashing(''.join([bin(ord(a))[2:].rjust(8, "0") for a in msg[:self.block]]))
            msg = msg[self.block:]
        msg = self.padding(msg, length)
        for a in range(len(msg) // self._b2):
            self.hashing(msg[a * self._b2:a * self._b2 + self._b2])

    def macAttack(self, newMsg, orgData, keyLen, ssHash, raw=False):
        self.check(keyLen, ssHash)
        self.sHash(ssHash)                
        extendLength = self.newLength(keyLen, orgData, newMsg)        
        msg = newMsg
        while len(msg) > self.block:
            self.hashing(''.join([bin(ord(a))[2:].rjust(8, "0") for a in msg[:self.block]]))
            msg = msg[self.block:]

        msg = self.padding(msg, extendLength)        

        for i in range(len(msg) // self._b2):
            self.hashing(msg[i * self._b2:i * self._b2 + self._b2])

        return self.hashPadding(keyLen, orgData, newMsg, raw=raw)

    def newHash(self):
        return ''.join( [ (('%0' + str(self._b1) + 'x') % (a)) for a in self.digest()])

    def __init__(self):
        self._b1 = self.block/8
        self._b2 = self.block*8

    def digest(self):
        return [self.__getattribute__(a) for a in dir(self) if match('^_h\d+$', a)]

    def sHash(self, ssHash):
        c = 0
        hashVals = [ int(ssHash[a:a+int(self._b1)],base=16) for a in range(0,len(ssHash), int(self._b1)) ]
        for hv in [ a for a in dir(self) if match('^_h\d+$', a) ]:
            self.__setattr__(hv, hashVals[c])        
            c+=1

    def check(self, keyLen, ssHash):
        if not isinstance(keyLen, int):
            raise TypeError('keyLen must be a valid integer')
        if keyLen < 1:
            raise ValueError('keyLen must be grater than 0')
        if not match('^[a-fA-F0-9]{' + str(len(self.newHash())) + '}$', ssHash):
            raise ValueError('ssHash must be a string of length ' + str(len(self.newHash())) + ' in hexlified format')
        
    def getBytes(self, byteVal):
        if byteVal < 0x20 or byteVal > 0x7e:
            return '\\x%02x' %(byteVal)
        else:    
            return chr(byteVal)

    def toByte(self, binary):
        return ''.join([ chr(int(binary[a:a+8],base=2)) for a in range(0,len(binary),8) ])

    def newLength(self, keyLen, orgData, newMsg):
        originalHashLength = int(ceil((keyLen+len(orgData)+self._b1+1)/float(self.block)) * self.block) 
        newHashLength = originalHashLength + len(newMsg) 
        return bin(newHashLength * 8)[2:].rjust(self.block, "0")

    def hashPadding(self, keyLen, orgData, newMsg, raw=False): 
        originalHashLength = bin((keyLen+len(orgData)) * 8)[2:].rjust(self.block, "0")    
        padData = ''.join(bin(ord(i))[2:].rjust(8, "0") for i in orgData) + "1"
        padData += "0" * (((self.block*7) - (len(padData)+(keyLen*8)) % self._b2) % self._b2) + originalHashLength 
        if not raw:
            return ''.join([ self.getBytes(int(padData[a:a+8],base=2)) for a in range(0,len(padData),8) ]) + newMsg
        else:
            return self.toByte(padData) + newMsg    

    def padding(self, msg, length):
        msg = ''.join(bin(ord(i))[2:].rjust(8, "0") for i in msg) + "1"    
        msg += "0" * (((self.block*7) - len(msg) % self._b2) % self._b2) + length
        return msg

def new(algorithm):
    obj = {'sha1': SHA1}[algorithm]()
    return obj

class SHA1 (hash):
    _h0, _h1, _h2, _h3, _h4, = (0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0)
    block = 64
    def hashing(self, chunk):
        lrot = lambda x, n: (x << n) | (x >> (32 - n))
        w = []
        for j in range(len(chunk) // 32):
            w.append(int(chunk[j * 32:j * 32 + 32], 2))
        for i in range(16, 80):
            w.append(lrot(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1)
                & 0xffffffff)
        a = self._h0
        b = self._h1
        c = self._h2
        d = self._h3
        e = self._h4
        for i in range(80):
            if i <= i <= 19:
                f, k = d ^ (b & (c ^ d)), 0x5a827999
            elif 20 <= i <= 39:
                f, k = b ^ c ^ d, 0x6ed9eba1
            elif 40 <= i <= 59:
                f, k = (b & c) | (d & (b | c)), 0x8f1bbcdc
            elif 60 <= i <= 79:
                f, k = b ^ c ^ d, 0xca62c1d6
            temp = lrot(a, 5) + f + e + k + w[i] & 0xffffffff
            a, b, c, d, e = temp, a, lrot(b, 30), c, d
        self._h0 = (self._h0 + a) & 0xffffffff
        self._h1 = (self._h1 + b) & 0xffffffff
        self._h2 = (self._h2 + c) & 0xffffffff
        self._h3 = (self._h3 + d) & 0xffffffff
        self._h4 = (self._h4 + e) & 0xffffffff

def sha1():
    return new('sha1')

sha = new('sha1')
''' Input parameters:  <new malicious text>, <original message>, <key length>, <hash value>'''
print (sha.macAttack( 'mtiwari','No one has completed Project #3 so give them all a 0.',16,'0543f18d6a0e780798b0c0c7e3e4676c5207b5ee'))
'''Output message in hex: <4e6f206f6e652068617320636f6d706c657465642050726f6a65637420233320736f2067697665207468656d20616c6c206120302e\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02286d746977617269'''
print (sha.newHash())
''' Output hash : <ba70e2a1ffe30bb7eabfea297c7632e94df60368>'''
