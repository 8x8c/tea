simple example of how one might implement a basic file encryption CLI in pure Rust (no external crates) using the Tiny Encryption Algorithm (TEA). Important caveats before we begin:

Security: TEA (and especially “vanilla” TEA) is not considered secure by modern standards and can be vulnerable to various attacks. It is used here only as a didactic example because it is short and relatively straightforward to implement from scratch.
Production Use: For real-world or production-grade encryption, you should rely on well-vetted libraries (e.g., RustCrypto crates, AES-GCM, or ring) and standard modes of operation (GCM, CBC, etc.).
Key Management / IV: Proper key derivation (e.g., via PBKDF2, Argon2) and randomness (for IVs, nonces, salts) are essential for secure encryption. This example uses neither.
With these disclaimers in mind, the code below shows how to implement a minimal CLI tool that (a) reads a file into memory, (b) encrypts or decrypts it in place using TEA in ECB-like fashion, and (c) writes the result back to disk.

TEA Overview
Tiny Encryption Algorithm operates on 64-bit blocks (two 32-bit words) using a 128-bit key (four 32-bit words). The core functions are tea_encrypt_block and tea_decrypt_block below.

tea_encrypt_block does 32 rounds of simple operations.
tea_decrypt_block does the inverse, also in 32 rounds.
