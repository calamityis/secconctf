from simon import SimonCipher
def test_simon64_96(key):
        #key = 0x131211100b0a090803020100
        plaintxt = 0x6d564d37426e6e71
        ciphertxt = 0xbb5d12ba422834b5
        block_size = 64
        key_size = 96
        c = SimonCipher(key, key_size, block_size, 'ECB')
        if c.encrypt(plaintxt) == ciphertxt:
            return hex(key)
        return 0
lib = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz_{}"
import itertools
for i in itertools.product(lib,repeat=4):
    d = ''.join(i)
    key = int(str('534543434f4e7b')+str(d.encode('hex'))+str('7d'),16)
    #key = int('534543434f4e7b41417d7d7d',16)
    #print key
    flag = test_simon64_96(key)
    if '53454343' in str(flag):
        print flag[2:-1].decode('hex')
