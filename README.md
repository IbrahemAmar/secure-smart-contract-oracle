```markdown
# Secure Smart Contract Data Feed (Encrypted Oracle Architecture)

An independent, zero-trust hybrid cryptographic pipeline designed to solve the **"Oracle Problem"** in blockchain architectures. This system enables secure, authenticated, and tamper-proof transmission of real-world data feeds to isolated smart contract environments.

To eliminate vulnerabilities inherent in high-level external libraries, the complete cryptographic pipeline was built completely from scratch—including Feistel scheduling, Galois Field polynomial reductions, modular inverses via the Extended Euclidean Algorithm, and elliptic curve scalar coordinate tracking.

## Architecture & Security Layers

The system employs a 3-tier hybrid cryptographic structure to ensure absolute Confidentiality, Integrity, and Authenticity (CIA triad).

1. **Symmetric Encryption (SM4-GCM):** Data payloads are encrypted using the Chinese commercial SM4 standard (a 32-round generalized Feistel block cipher) wrapped in Galois/Counter Mode (GCM). This provides high-throughput streaming capabilities and appends a 16-byte GHASH tag evaluated over the finite field $GF(2^{128})$ to guarantee data integrity.
2. **Asymmetric Key Encapsulation (EC El-Gamal):** To securely transmit the dynamic 128-bit SM4 session key without an asymmetric performance bottleneck, the key is mapped to an $(x, y)$ coordinate point on the standard `secp256k1` elliptic curve using Koblitz's embedding method and encapsulated via Elliptic Curve El-Gamal.
3. **Source Authentication (ECDSA):** Digital signatures are generated over the `secp256k1` curve. The smart contract validates the signature *before* attempting any decryption, creating an immediate defensive filter that drops malformed or unauthorized data packages "at the door" to conserve computing resources.

---

## File Structure

```text
├── ecc.py       # secp256k1 curve math, EC El-Gamal, and ECDSA implementations
├── sm4.py       # SM4 block cipher core and GCM mode (GHASH & CTR stream) logic
├── nodes.py     # Oracle Service (producer) and Smart Contract (consumer) abstractions
└── main.py      # End-to-end integration demo and pipeline validation tests

```

---

## Cryptographic Primitives Built From Scratch

* **Symmetric Block Cipher:** Complete implementation of the 32-round SM4 non-linear substitution and linear transformation steps.
* **Galois Field Operations:** Custom polynomial multiplication and reduction modulo $x^{128} + x^7 + x^2 + x + 1$ for the GCM authentication tag computation.
* **Elliptic Curve Math:** Point addition, doubling, and scalar multiplication via the double-and-add strategy over the prime field $\mathbb{F}_p$ defined by `secp256k1`.
* **Modular Arithmetic:** Extended Euclidean Algorithm used for calculating modular multiplicative inverses required for EC point math and ECDSA verification.

---

## Getting Started

### Prerequisites

* Python 3.10 or higher.
* Standard library components only (No external dependencies needed).

### Running the Demo

Execute the central pipeline execution script to see the data package generation, transmission encryption, smart contract consumption, and anti-tamper evaluation:

```bash
python main.py

```

### Expected Output

The demo verifies successful data recovery under normal operation and guarantees immediate transaction rejection if an adversary attempts to flip even a single byte of the ciphertext:

```text
============================================================
   Encrypted Smart Contract Data Feed – Demo
============================================================

[Oracle] Original data: {'asset': 'ETH/USD', 'price': 3412.75, ...}
[Oracle] Package generated with encrypted data and keys.

--- Contract consuming package ---
[Contract] Signature verified
[Contract] GCM authentication passed
[Contract] Decrypted data successfully: {'asset': 'ETH/USD', 'price': 3412.75, ...}

--- Tamper test (flip one byte in ciphertext) ---
ValueError: GCM authentication tag mismatch — data may be tampered!

```

---

## Technical Conclusions

* **Architectural Efficiency:** Combining high-performance symmetric block operations (SM4-GCM) with asymmetric EC primitives (`secp256k1`) provides robust production-grade security without compromising execution speed.
* **Early Defensiveness:** Validating the ECDSA signature prior to triggering key decapsulation effectively neutralizes Denial-of-Service (DoS) vectors targeting resource-constrained smart contracts.

```

```
