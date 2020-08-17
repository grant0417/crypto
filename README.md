# Crypto

WARNING: This crate is an implementation of some crypto related functions, never use any of these in
production, use OpenSSL, NaCl, or another lib that is audited.

The main purpose of this crate is for learning about common cryptographic function through implementing them. This can
also be a good resource for other to learn from as there are minimal external libraries used and each module is only
dependent on `crypto::utils` and the Rust standard library.

## Modules

* `crypto::aes` - An implementation of the Advanced Encryption Standard (AES), the most widely used block cipher.
* `crypto::mersenne_twister` - An implementation of the most common pseudo-random number generator, the Mersenne Twister.
* `crypto::dh` - An implementation of the Diffie-Hellman key exchange, a method for sharing cryptographic keys.
* `crypto::cryptanalysis` - Tools to attack crypto systems.
* `crypto::utils` - Wrappers and utilities for working with base64, hex, byte arrays, and random number generators.

## Todo

* `crypto::rsa` - An implementation of Rivest–Shamir–Adleman (RSA), one of the most widely used public-key ciphers.
* `crypyo::hash` - An implementation of common hashing function, MD5, SHA, etc.