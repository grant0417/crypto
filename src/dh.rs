use num::bigint::RandBigInt;
use num::BigUint;

/// Generates a random private Diffie-Hellman key
pub fn generate_private_key(p: &[u8]) -> Vec<u8> {
    let p = BigUint::from_bytes_be(p);

    let mut rng = rand::thread_rng();

    rng.gen_biguint_below(&p).to_bytes_be()
}

/// Generates a Diffie-Hellman public key from a private key
pub fn generate_public_key(p: &[u8], g: usize, private_key: &[u8]) -> Vec<u8> {
    let p = BigUint::from_bytes_be(p);
    let g = BigUint::from(g);

    let private_key = BigUint::from_bytes_be(private_key);

    g.modpow(&private_key, &p).to_bytes_be()
}

/// Derives the common secret from my private and their public keys
pub fn derive_shared_secret_key(p: &[u8], my_private: &[u8], their_public: &[u8]) -> Vec<u8> {
    let p = BigUint::from_bytes_be(p);
    let their_public = BigUint::from_bytes_be(their_public);
    let my_private = BigUint::from_bytes_be(my_private);

    their_public.modpow(&my_private, &p).to_bytes_be()
}

#[test]
fn test_diffie_hellman() {
    let p = crate::utils::hex_to_bytes("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024\
                                        e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd\
                                        3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec\
                                        6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f\
                                        24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361\
                                        c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552\
                                        bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff\
                                        fffffffffffff");
    let g = 2;

    let private_a = generate_private_key(&p);
    let private_b = generate_private_key(&p);

    let public_a = generate_public_key(&p, g, private_a.as_slice());
    let public_b = generate_public_key(&p, g, private_b.as_slice());

    let secret_a = derive_shared_secret_key(&p, private_a.as_slice(), public_b.as_slice());
    let secret_b = derive_shared_secret_key(&p, private_b.as_slice(), public_a.as_slice());

    assert_eq!(secret_a, secret_b)
}