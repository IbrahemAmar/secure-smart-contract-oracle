import time
from nodes import SmartContract, OracleService

def run_demo():
    print("=" * 60)
    print("   Encrypted Smart Contract Data Feed – Demo")
    print("=" * 60)

    contract = SmartContract()
    oracle   = OracleService()

    data = {
        "asset":      "ETH/USD",
        "price":      3412.75,
        "volume_24h": 1234567.89,
        "timestamp":  int(time.time()),
        "source":     "decentralized_aggregator"
    }
    print(f"\n[Oracle] Original data: {data}")

    pkg = oracle.produce(data, contract.pub)
    print(f"\n[Oracle] Package generated with encrypted data and keys.")
    print(f"[Oracle] Ciphertext (hex, first 32 chars): {pkg['ciphertext'][:32]}...")
    print(f"[Oracle] Auth tag: {pkg['auth_tag']}")
    print(f"[Oracle] IV: {pkg['iv']}")

    print("\n--- Contract consuming package ---")
    recovered = contract.consume(pkg)
    print(f"[Contract] Decrypted data successfully: {recovered}")

    # Tamper test
    print("\n--- Tamper test (flip one byte in ciphertext) ---")
    tampered_pkg = dict(pkg)
    ct_bytes = bytearray(bytes.fromhex(pkg["ciphertext"]))
    ct_bytes[0] ^= 0xFF
    tampered_pkg["ciphertext"] = bytes(ct_bytes).hex()
    try:
        contract.consume(tampered_pkg)
    except ValueError as e:
        print(f"[Contract] Tamper detected successfully: {e}")

    print("\n[Demo complete]")

if __name__ == "__main__":
    run_demo()