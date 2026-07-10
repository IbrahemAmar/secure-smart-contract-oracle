import os
import json
import time
from sm4 import SM4GCM, int_to_bytes
from ecc import (
    ECPoint, ec_keygen, key_to_point, point_to_key,
    ec_elgamal_encrypt, ec_elgamal_decrypt, ecdsa_sign, ecdsa_verify
)

class OracleService:
    def __init__(self):
        self.signing_priv, self.signing_pub = ec_keygen()
        print(f"[Oracle] Signing pubkey X: {hex(self.signing_pub.x)[:20]}...")

    def produce(self, data: dict, contract_pub: ECPoint) -> dict:
        sm4_key = os.urandom(16)
        iv      = os.urandom(12)
        payload = json.dumps(data).encode()
        aad     = b"smart_contract_oracle_v1"

        gcm = SM4GCM(sm4_key)
        ciphertext, auth_tag = gcm.encrypt(payload, iv, aad)

        key_point  = key_to_point(sm4_key)
        C1, C2     = ec_elgamal_encrypt(contract_pub, key_point)

        sign_data = (ciphertext + auth_tag
                     + int_to_bytes(C1.x,32) + int_to_bytes(C1.y,32)
                     + int_to_bytes(C2.x,32) + int_to_bytes(C2.y,32)
                     + iv)
        r, s = ecdsa_sign(self.signing_priv, sign_data)

        timestamp = int(time.time())
        return {
            "timestamp": timestamp,
            "ciphertext": ciphertext.hex(),
            "auth_tag":   auth_tag.hex(),
            "iv":         iv.hex(),
            "aad":        aad.hex(),
            "C1": {"x": hex(C1.x), "y": hex(C1.y)},
            "C2": {"x": hex(C2.x), "y": hex(C2.y)},
            "signature": {"r": hex(r), "s": hex(s)},
            "oracle_pub": {
                "x": hex(self.signing_pub.x),
                "y": hex(self.signing_pub.y)
            }
        }

class SmartContract:
    def __init__(self):
        self.priv, self.pub = ec_keygen()
        print(f"[Contract] Pubkey X: {hex(self.pub.x)[:20]}...")

    def consume(self, pkg: dict) -> dict:
        ciphertext = bytes.fromhex(pkg["ciphertext"])
        auth_tag   = bytes.fromhex(pkg["auth_tag"])
        iv         = bytes.fromhex(pkg["iv"])
        aad        = bytes.fromhex(pkg["aad"])
        C1 = ECPoint(int(pkg["C1"]["x"],16), int(pkg["C1"]["y"],16))
        C2 = ECPoint(int(pkg["C2"]["x"],16), int(pkg["C2"]["y"],16))
        r  = int(pkg["signature"]["r"],16)
        s  = int(pkg["signature"]["s"],16)
        oracle_pub = ECPoint(int(pkg["oracle_pub"]["x"],16), int(pkg["oracle_pub"]["y"],16))

        sign_data = (ciphertext + auth_tag
                     + int_to_bytes(C1.x,32) + int_to_bytes(C1.y,32)
                     + int_to_bytes(C2.x,32) + int_to_bytes(C2.y,32)
                     + iv)
        if not ecdsa_verify(oracle_pub, sign_data, r, s):
            raise ValueError("ECDSA signature INVALID - data rejected!")
        print("[Contract] Signature verified")

        key_point = ec_elgamal_decrypt(self.priv, C1, C2)
        sm4_key   = point_to_key(key_point)

        gcm = SM4GCM(sm4_key)
        plaintext = gcm.decrypt(ciphertext, iv, auth_tag, aad)
        print("[Contract] GCM authentication passed")
        return json.loads(plaintext)