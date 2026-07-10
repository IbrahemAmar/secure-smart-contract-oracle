import struct

# ─────────────────────────────────────────────────────────────
# Utilities
# ─────────────────────────────────────────────────────────────
def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def int_to_bytes(n: int, length: int) -> bytes:
    return n.to_bytes(length, 'big')

def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, 'big')

# ─────────────────────────────────────────────────────────────
# SM4 Block Cipher Core (GB/T 32907-2016)
# ─────────────────────────────────────────────────────────────
SM4_SBOX = [
    0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
    0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
    0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
    0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
    0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
    0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
    0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
    0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
    0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
    0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
    0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
    0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
    0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
    0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
    0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
    0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48,
]

SM4_FK = [0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC]
SM4_CK = [
    0x00070e15,0x1c232a31,0x383f464d,0x545b6269,
    0x70777e85,0x8c939aa1,0xa8afb6bd,0xc4cbd2d9,
    0xe0e7eef5,0xfc030a11,0x181f262d,0x343b4249,
    0x50575e65,0x6c737a81,0x888f969d,0xa4abb2b9,
    0xc0c7ced5,0xdce3eaf1,0xf8ff060d,0x141b2229,
    0x30373e45,0x4c535a61,0x686f767d,0x848b9299,
    0xa0a7aeb5,0xbcc3cad1,0xd8dfe6ed,0xf4fb0209,
    0x10171e25,0x2c333a41,0x484f565d,0x646b7279,
]

def _sm4_tau(a: int) -> int:
    return (SM4_SBOX[(a>>24)&0xff]<<24|(SM4_SBOX[(a>>16)&0xff]<<16)|
            SM4_SBOX[(a>>8)&0xff]<<8|SM4_SBOX[a&0xff])

def _rotl32(x: int, n: int) -> int:
    return ((x << n) | (x >> (32-n))) & 0xFFFFFFFF

def _sm4_L(b: int) -> int:
    return b ^ _rotl32(b,2) ^ _rotl32(b,10) ^ _rotl32(b,18) ^ _rotl32(b,24)

def _sm4_L2(b: int) -> int:
    return b ^ _rotl32(b,13) ^ _rotl32(b,23)

def _sm4_T(a: int) -> int:  return _sm4_L(_sm4_tau(a))
def _sm4_T2(a: int) -> int: return _sm4_L2(_sm4_tau(a))

def _sm4_key_expand(key: bytes) -> list:
    assert len(key) == 16
    MK = [int.from_bytes(key[i*4:i*4+4], 'big') for i in range(4)]
    K = [MK[i] ^ SM4_FK[i] for i in range(4)]
    rk = []
    for i in range(32):
        t = K[1] ^ K[2] ^ K[3] ^ SM4_CK[i]
        rk.append(K[0] ^ _sm4_T2(t))
        K = K[1:] + [rk[-1]]
    return rk

def _sm4_block(block: bytes, rk: list) -> bytes:
    X = [int.from_bytes(block[i*4:i*4+4], 'big') for i in range(4)]
    for i in range(32):
        t = X[1] ^ X[2] ^ X[3] ^ rk[i]
        X = X[1:] + [X[0] ^ _sm4_T(t)]
    result = X[3::-1]
    return b''.join(v.to_bytes(4,'big') for v in result)

class SM4:
    def __init__(self, key: bytes):
        self._erk = _sm4_key_expand(key)
        self._drk = self._erk[::-1]

    def encrypt_block(self, block: bytes) -> bytes:
        return _sm4_block(block, self._erk)

    def decrypt_block(self, block: bytes) -> bytes:
        return _sm4_block(block, self._drk)

# ─────────────────────────────────────────────────────────────
# GHASH Engine
# ─────────────────────────────────────────────────────────────
def _ghash_mul(X: int, Y: int) -> int:
    R = 0xE1000000000000000000000000000000
    Z, V = 0, Y
    for i in range(128):
        if (X >> (127-i)) & 1:
            Z ^= V
        lsb = V & 1
        V >>= 1
        if lsb:
            V ^= R
    return Z

class GHASH:
    def __init__(self, H: bytes):
        self._H = bytes_to_int(H)

    def _pad16(self, data: bytes) -> bytes:
        r = len(data) % 16
        return data + (b'\x00' * ((16 - r) % 16))

    def compute(self, aad: bytes, ciphertext: bytes) -> bytes:
        data = self._pad16(aad) + self._pad16(ciphertext)
        data += struct.pack('>QQ', len(aad)*8, len(ciphertext)*8)
        Y = 0
        for i in range(0, len(data), 16):
            block = bytes_to_int(data[i:i+16])
            Y = _ghash_mul(Y ^ block, self._H)
        return int_to_bytes(Y, 16)

# ─────────────────────────────────────────────────────────────
# SM4-GCM Top Level
# ─────────────────────────────────────────────────────────────
class SM4GCM:
    TAG_LEN = 16

    def __init__(self, key: bytes):
        self._sm4 = SM4(key)
        H = self._sm4.encrypt_block(b'\x00'*16)
        self._ghash = GHASH(H)

    def _inc32(self, ctr: bytearray) -> bytearray:
        n = struct.unpack_from('>I', ctr, 12)[0]
        struct.pack_into('>I', ctr, 12, (n+1) & 0xFFFFFFFF)
        return ctr

    def _ctr_stream(self, j0: bytes, length: int) -> bytes:
        ctr = bytearray(j0)
        self._inc32(ctr)
        stream = b''
        while len(stream) < length:
            stream += self._sm4.encrypt_block(bytes(ctr))
            self._inc32(ctr)
        return stream[:length]

    def _build_j0(self, iv: bytes) -> bytes:
        if len(iv) == 12:
            return iv + b'\x00\x00\x00\x01'
        pad = self._ghash._pad16(iv)
        pad += b'\x00'*8 + struct.pack('>Q', len(iv)*8)
        return int_to_bytes(_ghash_mul(0, bytes_to_int(pad)), 16)

    def encrypt(self, plaintext: bytes, iv: bytes, aad: bytes = b'') -> tuple:
        j0 = self._build_j0(iv)
        ciphertext = xor_bytes(plaintext, self._ctr_stream(j0, len(plaintext)))
        tag_stream = self._sm4.encrypt_block(j0)
        ghash_val = self._ghash.compute(aad, ciphertext)
        tag = xor_bytes(tag_stream, ghash_val)
        return ciphertext, tag

    def decrypt(self, ciphertext: bytes, iv: bytes, tag: bytes, aad: bytes = b'') -> bytes:
        j0 = self._build_j0(iv)
        ghash_val = self._ghash.compute(aad, ciphertext)
        tag_stream = self._sm4.encrypt_block(j0)
        expected_tag = xor_bytes(tag_stream, ghash_val)
        diff = 0
        for a, b in zip(expected_tag, tag):
            diff |= a ^ b
        if diff != 0:
            raise ValueError("GCM authentication tag mismatch — data may be tampered!")
        return xor_bytes(ciphertext, self._ctr_stream(j0, len(ciphertext)))