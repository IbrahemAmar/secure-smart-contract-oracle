import os
import hashlib
from sm4 import int_to_bytes, bytes_to_int

# secp256k1 parameters
_P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_A  = 0
_B  = 7
_Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
_N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def sha256_int(data: bytes) -> int:
    return bytes_to_int(sha256(data))

class ECPoint:
    def __init__(self, x, y):
        self.x = x  # None means point at infinity
        self.y = y

    @classmethod
    def infinity(cls):
        return cls(None, None)

    def is_infinity(self):
        return self.x is None

    def __eq__(self, other):
        return self.x == other.x and self.y == other.y

    def __neg__(self):
        if self.is_infinity(): return self
        return ECPoint(self.x, (-self.y) % _P)

    def __add__(self, other):
        if self.is_infinity(): return other
        if other.is_infinity(): return self
        if self.x == other.x:
            if (self.y + other.y) % _P == 0:
                return ECPoint.infinity()
            return self._double()
        lam = (other.y - self.y) * pow(other.x - self.x, _P-2, _P) % _P
        x3 = (lam*lam - self.x - other.x) % _P
        y3 = (lam*(self.x - x3) - self.y) % _P
        return ECPoint(x3, y3)

    def _double(self):
        lam = (3*self.x*self.x + _A) * pow(2*self.y, _P-2, _P) % _P
        x3 = (lam*lam - 2*self.x) % _P
        y3 = (lam*(self.x - x3) - self.y) % _P
        return ECPoint(x3, y3)

    def __rmul__(self, k):
        return self.__mul__(k)

    def __mul__(self, k):
        k = k % _N
        result, addend = ECPoint.infinity(), self
        while k:
            if k & 1:
                result = result + addend
            addend = addend + addend
            k >>= 1
        return result

    def compress(self) -> bytes:
        prefix = b'\x02' if self.y % 2 == 0 else b'\x03'
        return prefix + int_to_bytes(self.x, 32)

G = ECPoint(_Gx, _Gy)

def ec_keygen() -> tuple:
    priv = bytes_to_int(os.urandom(32)) % (_N - 1) + 1
    pub  = priv * G
    return priv, pub

# ─────────────────────────────────────────────────────────────
# EC El-Gamal (Key Delivery)
# ─────────────────────────────────────────────────────────────
def ec_elgamal_encrypt(pub: ECPoint, message_point: ECPoint) -> tuple:
    k = bytes_to_int(os.urandom(32)) % (_N - 1) + 1
    C1 = k * G
    C2 = message_point + k * pub
    return C1, C2

def ec_elgamal_decrypt(priv: int, C1: ECPoint, C2: ECPoint) -> ECPoint:
    return C2 + (-(priv * C1))

def point_to_key(pt: ECPoint) -> bytes:
    x = pt.x
    delta = (x >> 128) & 0xFFFF
    k_int = (x - delta * 2**128) >> 0
    return int_to_bytes(k_int & ((1 << 128) - 1), 16)

def key_to_point(key_bytes: bytes) -> ECPoint:
    k_int = bytes_to_int(key_bytes)
    for delta in range(1000):
        x = (k_int + delta * (2**128)) % _P
        rhs = (pow(x, 3, _P) + _B) % _P
        y = pow(rhs, (_P+1)//4, _P)
        if pow(y, 2, _P) == rhs:
            return ECPoint(x, y)
    raise ValueError("Could not embed key as point")

# ─────────────────────────────────────────────────────────────
# ECDSA (Digital Signatures)
# ─────────────────────────────────────────────────────────────
def ecdsa_sign(priv: int, message: bytes) -> tuple:
    z = sha256_int(message)
    while True:
        k = bytes_to_int(os.urandom(32)) % (_N - 1) + 1
        R = k * G
        r = R.x % _N
        if r == 0: continue
        s = (pow(k, _N-2, _N) * (z + r*priv)) % _N
        if s == 0: continue
        return r, s

def ecdsa_verify(pub: ECPoint, message: bytes, r: int, s: int) -> bool:
    if not (1 <= r < _N and 1 <= s < _N): return False
    z = sha256_int(message)
    w  = pow(s, _N-2, _N)
    u1 = (z * w) % _N
    u2 = (r * w) % _N
    X  = u1*G + u2*pub
    if X.is_infinity(): return False
    return (X.x % _N) == r