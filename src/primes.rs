use num::{BigUint, One, Integer, bigint::RandBigInt};

/// Probabilistic test that takes an odd, n > 3 and returns true if it is
/// likely a prime or false if it is composite.
///
/// https://en.wikipedia.org/wiki/Miller-Rabin_primality_test
pub fn miller_rabin_test(n: &BigUint, rounds: u64) -> bool {
    if n % 2u64 == BigUint::from(0u64) || n <= &BigUint::from(3u64) {
        return false
    }

    let one = BigUint::one();
    let two = BigUint::from(2u64);
    let n_1 = n - &one;

    let mut rng = rand::thread_rng();

    let (r, d) = factor_out_powers(&n_1);

    'WitnessLoop: for _ in 0..rounds {
        let random_int = rng.gen_biguint_range(&two, &n_1);
        let x = random_int.modpow(&d, &n);
        if x.is_one() || x == n_1 {
            continue 'WitnessLoop;
        }
        for _ in 0..r-1 {
            let x = x.modpow(&two, &n);
            if x == one {
                return false;
            } else if x == n_1 {
                continue 'WitnessLoop;
            }
        }
        return false
    }
    true
}

// TODO: Implement prime lucas test

// TODO: Implement Baillie-PSW test

/// Factors out powers of 2 from a BigUint
///
/// Returns (power: u64, constant: power) such that n = 2^power * constant
fn factor_out_powers(n: &BigUint) -> (u64, BigUint) {
    let power = n.trailing_zeros().unwrap_or(0);
    let constant = n >> power;

    (power, constant)
}

/// Generates a prime with a size of `bytes`.
///
/// Warning: Is very slow for large sizes.
pub fn gen_prime(bits: u64, rounds: u64) -> BigUint {
    let mut rng = rand::thread_rng();
    let mut potential_prime = rng.gen_biguint(bits);
    if potential_prime.is_even() {
        potential_prime += 1u64;
    }

    loop {
        if miller_rabin_test(&potential_prime, rounds) {
            break
        } else {
            potential_prime += 2u64;
        }
    }

    potential_prime
}

#[test]
fn is_prime_test() {
    let semi_prime =
        BigUint::parse_bytes("26062623684139844921529879266674432197085925380486406416164785191859999628542069361450283931914514618683512198164805919882053057222974116478065095809832377336510711545759".as_bytes(), 10).unwrap();

    assert_eq!(miller_rabin_test(&semi_prime, 100), false);

    let prime =
        BigUint::parse_bytes("64135289477071580278790190170577389084825014742943447208116859632024532344630238623598752668347708737661925585694639798853367".as_bytes(), 10).unwrap();

    assert_eq!(miller_rabin_test(&prime, 100), true);
}

#[test]
fn gen_prime_test() {
    let prime = gen_prime(10, 40);
    eprintln!("{}", prime);
}