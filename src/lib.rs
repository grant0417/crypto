//! This crate is an implementation of some crypto related function, never use any of these in
//! production, use OpenSSL, NaCl, or another lib that is audited.

#![warn(missing_copy_implementations, missing_debug_implementations, missing_docs, trivial_casts, trivial_numeric_casts)]

/// [Advanced Encryption Standard (AES)](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
///
/// A block cipher also known as Rijndael
///
/// Note: block has a length of 16 and contains `u8`
pub mod aes;

/// [Diffie–Hellman](https://en.wikipedia.org/wiki/Diffie–Hellman_key_exchange)
///
/// A method for getting a common key for two people with each having a public and private key.
pub mod dh;

/// [RSA (Rivest–Shamir–Adleman)](https://en.wikipedia.org/wiki/RSA_(cryptosystem))
///
/// A public-key crypto system.
pub mod rsa;

/// [Mersenne Twister](https://en.wikipedia.org/wiki/Mersenne_Twister)
///
/// A pseudo-random number generator. Not cryptographically secure.
pub mod mersenne_twister;

/// Tools for generating primes and testing primarily. Useful for RSA.
pub mod primes;

/// Cryptanalysis tools
///
/// Used mostly for the [Cryptopals Crypto Challenge](https://cryptopals.com/)
pub mod cryptanalysis;

/// Misc utilities such as bit manipulation and byte conversion
///
/// Note: Bytes are represented by `u8`
pub mod utils;
