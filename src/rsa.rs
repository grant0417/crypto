use crate::primes;
use num::{BigUint, Zero, One, BigInt};
use num::bigint::ToBigInt;

/// RSA Public Key containing e and n.
#[derive(Debug)]
pub struct RSAPublicKey {
    e: Vec<u8>,
    n: Vec<u8>,
}

/// RSA Private Key containing d and n.
#[derive(Debug)]
pub struct RSAPrivateKey {
    d: Vec<u8>,
    n: Vec<u8>,
}

/// Generates a keypair of a `RSAPublicKey` and `RSAPrivateKey`.
pub fn rsa_generate_keypair(e: u64, key_length: u64, rounds: u64) -> (RSAPublicKey, RSAPrivateKey) {
    let e = BigUint::from(e);

    let mut p = primes::gen_prime(key_length / 2, rounds);
    while &p % &e == BigUint::one() {
        p = primes::gen_prime(key_length / 2, rounds);
    }

    let mut q = primes::gen_prime(key_length - key_length / 2, rounds);
    while &q % &e == BigUint::one() {
        q = primes::gen_prime(key_length - key_length / 2, rounds);
    }

    let n = &p * &q;
    let et = (&p - 1u64) * (&q - 1u64);

    let d = modinv(&e, &et).unwrap();

    let public_key = RSAPublicKey { e: e.to_bytes_be(), n: n.to_bytes_be() };
    let private_key = RSAPrivateKey { d: d.to_bytes_be(), n: n.to_bytes_be() };

    (public_key, private_key)
}

/// Encrypts `plaintext` using the public `key`.
pub fn rsa_encrypt(plaintext: &[u8], key: RSAPublicKey) -> Vec<u8> {
    let m = BigUint::from_bytes_be(plaintext);
    let e = BigUint::from_bytes_be(&*key.e);
    let n = BigUint::from_bytes_be(&*key.n);

    let ciphertext = m.modpow(&e, &n);

    ciphertext.to_bytes_be()
}

/// Decrypts `ciphertext` using the private `key`.
pub fn rsa_decrypt(ciphertext: &[u8], key: RSAPrivateKey) -> Vec<u8> {
    let c = BigUint::from_bytes_be(ciphertext);
    let d = BigUint::from_bytes_be(&*key.d);
    let n = BigUint::from_bytes_be(&*key.n);

    let plaintext = c.modpow(&d, &n);

    plaintext.to_bytes_be()
}

/// Modular Inverse
fn modinv(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    let m = m.to_bigint().unwrap();
    let (g, x, _) = egcd(&a.to_bigint().unwrap(), &m);
    if g != BigInt::one() {
        None
    } else {
        Some(((x % &m + &m) % &m).to_biguint().unwrap())
    }
}

/// Extended GCD
fn egcd(a: &BigInt, b: &BigInt) -> (BigInt, BigInt, BigInt) {
    if a == &BigInt::zero() {
        (b.clone(), BigInt::zero(), BigInt::one())
    } else {
        let (g, x, y) = egcd(&(b % a), a);
        (g, y - (b / a) * &x, x)
    }
}

#[test]
fn test_rsa() {
    let (public_key, private_key) = rsa_generate_keypair(3, 2048, 16);

    let plaintext = b"Hello there";

    let ciphertext = rsa_encrypt(plaintext, public_key);

    let decoded_ciphertext = rsa_decrypt(ciphertext.as_slice(), private_key);

    assert_eq!(plaintext, decoded_ciphertext.as_slice());
}
