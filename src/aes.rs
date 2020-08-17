use crate::utils;
use std::convert::TryInto;

/// Shifts `row` left by `shift` in the block `block`.
///
/// Panics if `row` is >3
fn shift_row_left(block: &mut [u8], row: usize, shift: usize) {
    if row > 3 {
        panic!("Row index out of range")
    }
    let shift = shift % 4;
    match shift {
        0 => {}
        1 => {
            let tmp = columns_of_block(block, 0)[row];
            columns_of_block(block, 0)[row] = columns_of_block(block, 1)[row];
            columns_of_block(block, 1)[row] = columns_of_block(block, 2)[row];
            columns_of_block(block, 2)[row] = columns_of_block(block, 3)[row];
            columns_of_block(block, 3)[row] = tmp;
        }
        2 => {
            let tmp = columns_of_block(block, 3)[row];
            columns_of_block(block, 3)[row] = columns_of_block(block, 1)[row];
            columns_of_block(block, 1)[row] = tmp;

            let tmp = columns_of_block(block, 2)[row];
            columns_of_block(block, 2)[row] = columns_of_block(block, 0)[row];
            columns_of_block(block, 0)[row] = tmp;
        }
        3 => {
            let tmp = columns_of_block(block, 0)[row];
            columns_of_block(block, 0)[row] = columns_of_block(block, 3)[row];
            columns_of_block(block, 3)[row] = columns_of_block(block, 2)[row];
            columns_of_block(block, 2)[row] = columns_of_block(block, 1)[row];
            columns_of_block(block, 1)[row] = tmp;
        }
        _ => unreachable!(),
    }
}

/// Indexes block by column
fn columns_of_block(block: &mut [u8], column: usize) -> &mut [u8] {
    match column {
        0 => &mut block[0..=3],
        1 => &mut block[4..=7],
        2 => &mut block[8..=11],
        3 => &mut block[12..=15],
        _ => panic!("Index out of range."),
    }
}

const fn rotl8(x: u8, shift: u8) -> u8 {
    (x << shift) | (x >> (8 - shift))
}

lazy_static! {
    /// A lookup table build statically for the AES substitution box.
    /// The first part of the tuple is the s-box and the second part is
    /// the inverse s-box.
    ///
    /// https://en.wikipedia.org/wiki/Rijndael_S-box
    static ref SBOX: ([u8; 256], [u8; 256]) = {
        let mut sbox = [0; 256];
        let mut inv_sbox = [0; 256];

        let mut p: u8 = 1;
        let mut q: u8 = 1;

        loop {
            p = p ^ (p << 1) ^ (if p & 0x80 == 0 { 0 } else { 0x1B });

            q ^= q << 1;
            q ^= q << 2;
            q ^= q << 4;
            q ^= if q & 0x80 == 0 { 0 } else { 0x09 };

            let s = q ^ rotl8(q, 1) ^ rotl8(q, 2) ^ rotl8(q, 3) ^ rotl8(q, 4) ^ 0x63;

            sbox[p as usize] = s;
            inv_sbox[s as usize] = p;

            if p == 1 {
                break;
            }
        }

        sbox[0] = 0x63;

        (sbox, inv_sbox)
    };
}

/// Modes of AES
#[derive(Debug, Clone)]
pub enum Mode {
    /// Electronic Code Book
    ECB,
    /// Cipher Block Chaining - The argument is the initialization vector
    CBC(Vec<u8>),
}

/// Encrypts data using a specified key and mode
pub fn aes_encrypt(data: &[u8], key: &AESKey, mode: &Mode) -> Vec<u8> {
    let mut data = Vec::from(data);
    utils::pad_pkcs7(&mut data, 16);
    match mode {
        Mode::ECB => {
            aes_ecb(data.as_mut_slice(), key);
        }
        Mode::CBC(iv) => {
            aes_cbc(data.as_mut_slice(), key, iv);
        }
    }
    data
}

/// Decrypts data using a specified key and mode
///
/// Will panic if the data is not properly padded. `aes_encrypt` will always
/// be able to be decrypted without panicking.
pub fn aes_decrypt(data: &[u8], key: &AESKey, mode: &Mode) -> Vec<u8> {
    let mut data = Vec::from(data);
    match mode {
        Mode::ECB => {
            inv_aes_ecb(data.as_mut_slice(), key);
        }
        Mode::CBC(iv) => {
            inv_aes_cbc(data.as_mut_slice(), key, iv);
        }
    }
    utils::remove_padding_pkcs8(&mut data).expect("The data was not properly padded");
    data
}

/// Runs the AES algorithm on a single block
pub fn aes(block: &mut [u8], key: &AESKey) {
    let expanded_key = key_expansion(key);
    add_round_key(block, expanded_key[0].as_slice());
    for i in 1..expanded_key.len() - 1 {
        round(block, expanded_key[i].as_slice());
    }
    final_round(block, expanded_key[expanded_key.len() - 1].as_slice());
}

/// Runs the inverse AES algorithm on a single block
pub fn inv_aes(block: &mut [u8], key: &AESKey) {
    let expanded_key = key_expansion(key);
    inv_final_round(block, expanded_key[expanded_key.len() - 1].as_slice());
    for i in (1..expanded_key.len() - 1).rev() {
        inv_round(block, expanded_key[i].as_slice());
    }
    add_round_key(block, expanded_key[0].as_slice());
}

/// Runs the AES algorithm on a multiple of blocks in ECB mode
///
/// If `bytes` is not a multiple of 16 `aes_ecb` will panic
pub fn aes_ecb(bytes: &mut [u8], key: &AESKey) {
    if bytes.len() % 16 != 0 {
        panic!("AES requires a code of a length dividable by 16");
    }
    for i in 0..bytes.len() / 16 {
        aes(&mut bytes[i * 16..i * 16 + 16], &key);
    }
}

/// Runs the inverse AES algorithm on a multiple of blocks in ECB mode
///
/// If `bytes` is not a multiple of 16 `inv_aes_ecb` will panic
pub fn inv_aes_ecb(bytes: &mut [u8], key: &AESKey) {
    if bytes.len() % 16 != 0 {
        panic!("AES requires a code of a length dividable by 16");
    }
    for i in 0..bytes.len() / 16 {
        inv_aes(&mut bytes[i * 16..i * 16 + 16], &key);
    }
}

/// Runs the AES algorithm on a multiple of blocks in CBC mode
///
/// If `bytes` is not a multiple of 16 `aes_cbc` will panic.
///
/// If `iv`is not a length of 16 `aes_cbc` will panic.
pub fn aes_cbc(bytes: &mut [u8], key: &AESKey, iv: &[u8]) {
    if bytes.len() % 16 != 0 {
        panic!("AES requires a code of a length dividable by 16");
    }

    if iv.len() != 16 {
        panic!("IV must be 16 bytes long");
    }

    let mut previous = [0; 16];
    previous.copy_from_slice(iv);

    for i in 0..bytes.len() / 16 {
        add_round_key(&mut bytes[i * 16..i * 16 + 16], &previous);
        aes(&mut bytes[i * 16..i * 16 + 16], &key);
        previous = bytes[i * 16..i * 16 + 16].try_into().unwrap();
    }
}

/// Runs the inverse AES algorithm on a multiple of blocks in CBC mode
///
/// If `bytes` is not a multiple of 16 `inv_aes_cbc` will panic.
///
/// If `iv`is not a length of 16 `inv_aes_cbc` will panic.
pub fn inv_aes_cbc(bytes: &mut [u8], key: &AESKey, iv: &[u8]) {
    if bytes.len() % 16 != 0 {
        panic!("AES requires a code of a length dividable by 16");
    }

    if iv.len() != 16 {
        panic!("IV must be 16 bytes long");
    }

    let mut previous = [0; 16];
    previous.copy_from_slice(iv);


    for i in 0..bytes.len() / 16 {
        let tmp = bytes[i * 16..i * 16 + 16].try_into().unwrap();
        inv_aes(&mut bytes[i * 16..i * 16 + 16], &key);
        add_round_key(&mut bytes[i * 16..i * 16 + 16], &previous);
        previous = tmp;
    }
}

/// The AES key for a given key length
#[derive(Debug, Clone, Copy)]
pub enum AESKey {
    /// AES-128 Key
    AES128([u32; 4]),
    /// AES-192 Key
    AES192([u32; 6]),
    /// AES-256 Key
    AES256([u32; 8]),
}

impl AESKey {
    /// Returns an `AESKey` of a given size in bits.
    pub fn new(bits: usize) -> Option<Self> {
        if bits == 128 {
            Some(AESKey::AES128([0; 4]))
        } else if bits == 192 {
            Some(AESKey::AES192([0; 6]))
        } else if bits == 256 {
            Some(AESKey::AES256([0; 8]))
        } else {
            None
        }
    }

    /// Returns an `AESKey` derived from a byte slice.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let bytes_len = bytes.len();
        if bytes_len == 16 {
            let i0 = u8_slice_to_u32(&bytes[0..4]).unwrap();
            let i1 = u8_slice_to_u32(&bytes[4..8]).unwrap();
            let i2 = u8_slice_to_u32(&bytes[8..12]).unwrap();
            let i3 = u8_slice_to_u32(&bytes[12..16]).unwrap();
            Some(AESKey::AES128([i0, i1, i2, i3]))
        } else if bytes_len == 24 {
            let i0 = u8_slice_to_u32(&bytes[0..4]).unwrap();
            let i1 = u8_slice_to_u32(&bytes[4..8]).unwrap();
            let i2 = u8_slice_to_u32(&bytes[8..12]).unwrap();
            let i3 = u8_slice_to_u32(&bytes[12..16]).unwrap();
            let i4 = u8_slice_to_u32(&bytes[16..20]).unwrap();
            let i5 = u8_slice_to_u32(&bytes[20..24]).unwrap();
            Some(AESKey::AES192([i0, i1, i2, i3, i4, i5]))
        } else if bytes_len == 32 {
            let i0 = u8_slice_to_u32(&bytes[0..4]).unwrap();
            let i1 = u8_slice_to_u32(&bytes[4..8]).unwrap();
            let i2 = u8_slice_to_u32(&bytes[8..12]).unwrap();
            let i3 = u8_slice_to_u32(&bytes[12..16]).unwrap();
            let i4 = u8_slice_to_u32(&bytes[16..20]).unwrap();
            let i5 = u8_slice_to_u32(&bytes[20..24]).unwrap();
            let i6 = u8_slice_to_u32(&bytes[24..28]).unwrap();
            let i7 = u8_slice_to_u32(&bytes[28..32]).unwrap();
            Some(AESKey::AES256([i0, i1, i2, i3, i4, i5, i6, i7]))
        } else {
            None
        }
    }

    /// Randomizes a key
    pub fn randomize_key(&mut self) {
        match self {
            AESKey::AES128(ref mut a) => a.copy_from_slice(utils::random_u32s(4).as_slice()),
            AESKey::AES192(ref mut a) => a.copy_from_slice(utils::random_u32s(6).as_slice()),
            AESKey::AES256(ref mut a) => a.copy_from_slice(utils::random_u32s(8).as_slice()),
        };
    }
}

/// The AES key expansion algorithm that returns a Vec of each round's Vec of bytes
///
/// https://en.wikipedia.org/wiki/AES_key_schedule
fn key_expansion(key: &AESKey) -> Vec<Vec<u8>> {
    let (key_u32, rounds) = match &key {
        AESKey::AES128(k) => (k.as_ref(), 11),
        AESKey::AES192(k) => (k.as_ref(), 13),
        AESKey::AES256(k) => (k.as_ref(), 15),
    };
    let n = key_u32.len();

    let mut expanded_keys: Vec<u32> = Vec::with_capacity(4 * rounds);

    // https://en.wikipedia.org/wiki/AES_key_schedule#Round_constants
    let mut rc_list = Vec::with_capacity(rounds);

    let mut prev_rc: u8 = 1;
    rc_list.push(0);
    for i in 1..=10 {
        let rc: u8 = if i == 1 {
            1
        } else if i > 1 && (prev_rc < 0x80) {
            prev_rc.overflowing_mul(2).0
        } else {
            (prev_rc.overflowing_mul(2).0) ^ 0x1B
        };
        rc_list.push(rc as u32);
        prev_rc = rc;
    }

    for i in 0..4 * rounds {
        if i < n {
            expanded_keys.push(*key_u32.get(i).unwrap());
        } else if i >= n && i % n == 0 {
            expanded_keys.push(
                expanded_keys[i - n]
                    ^ sub_word(expanded_keys[i - 1].rotate_right(8))
                    ^ rc_list[i / 4],
            )
        } else if i >= n && n > 6 && i % n == 4 {
            expanded_keys.push(expanded_keys[i - n] ^ sub_word(expanded_keys[i - 1]))
        } else {
            expanded_keys.push(expanded_keys[i - n] ^ expanded_keys[i - 1]);
        }
    }

    let mut expanded_byte_keys = Vec::with_capacity(rounds);

    for i in 0..rounds {
        let mut round_key: Vec<u8> = Vec::with_capacity(16);
        let mut key1: Vec<u8> = expanded_keys[i * 4]
            .to_ne_bytes()
            .iter().copied()
            .collect();

        let mut key2: Vec<u8> = expanded_keys[i * 4 + 1]
            .to_ne_bytes()
            .iter().copied()
            .collect();

        let mut key3: Vec<u8> = expanded_keys[i * 4 + 2]
            .to_ne_bytes()
            .iter().copied()
            .collect();

        let mut key4: Vec<u8> = expanded_keys[i * 4 + 3]
            .to_ne_bytes()
            .iter().copied()
            .collect();

        round_key.append(&mut key1);
        round_key.append(&mut key2);
        round_key.append(&mut key3);
        round_key.append(&mut key4);
        expanded_byte_keys.push(round_key);
    }

    expanded_byte_keys
}

/// Substitutes each byte in a `u32` using the s-box
fn sub_word(word: u32) -> u32 {
    let bytes: Vec<u8> = word
        .to_ne_bytes()
        .iter()
        .map(|b| SBOX.0[*b as usize])
        .collect();

    u8_slice_to_u32(bytes.as_slice()).unwrap()
}

/// Transforms a slice of 4 bytes to a u32.
fn u8_slice_to_u32(bytes: &[u8]) -> Option<u32> {
    if bytes.len() == 4 {
        let (int_bytes, _) = bytes.split_at(std::mem::size_of::<u32>());
        Some(u32::from_ne_bytes(int_bytes.try_into().ok()?))
    } else {
        None
    }
}

/// Runs a round of the AES algorithm on a given block.
fn round(block: &mut [u8], expanded_key: &[u8]) {
    sub_bytes(block);
    shift_rows(block);
    mix_columns(block);
    add_round_key(block, expanded_key);
}

/// Runs a round of the inverse AES algorithm on a given block.
fn inv_round(block: &mut [u8], expanded_key: &[u8]) {
    add_round_key(block, expanded_key);
    inv_mix_columns(block);
    inv_shift_rows(block);
    inv_sub_bytes(block);
}

/// Runs the final round of the AES algorithm on a given block.
fn final_round(block: &mut [u8], expand_key: &[u8]) {
    sub_bytes(block);
    shift_rows(block);
    add_round_key(block, expand_key);
}

/// Runs the final round of the inverse AES algorithm on a given block.
fn inv_final_round(block: &mut [u8], expand_key: &[u8]) {
    add_round_key(block, expand_key);
    inv_shift_rows(block);
    inv_sub_bytes(block);
}

/// Substitutes the bytes in a block with the s-box value.
fn sub_bytes(block: &mut [u8]) {
    for byte in block {
        *byte = SBOX.0[*byte as usize];
    }
}

/// Substitutes the bytes in a block with the inverse s-box value.
fn inv_sub_bytes(block: &mut [u8]) {
    for byte in block {
        *byte = SBOX.1[*byte as usize];
    }
}

/// Shifts the rows according to the AES algorithm.
///
/// The first row is not shifted
///
/// The second row is shifted left 1
///
/// The third row is shifted left 2
///
/// The fourth row is shifted left 3
fn shift_rows(block: &mut [u8]) {
    shift_row_left(block, 1, 1);
    shift_row_left(block, 2, 2);
    shift_row_left(block, 3, 3);
}

/// Shifts the rows according to the AES algorithm.
///
/// The first row is not shifted
///
/// The second row is shifted right 1
///
/// The third row is shifted right 2
///
/// The fourth row is shifted right 3
fn inv_shift_rows(block: &mut [u8]) {
    shift_row_left(block, 1, 3);
    shift_row_left(block, 2, 2);
    shift_row_left(block, 3, 1);
}

/// Runs the mix column algorithm on each column
///
/// https://en.wikipedia.org/wiki/Rijndael_MixColumns
fn mix_columns(block: &mut [u8]) {
    for c in 0..4 {
        mix_column(&mut columns_of_block(block, c))
    }
}

/// Runs the inverse mix column algorithm on each column
///
/// https://en.wikipedia.org/wiki/Rijndael_MixColumns#InverseMixColumns
fn inv_mix_columns(block: &mut [u8]) {
    for c in 0..4 {
        inv_mix_column(&mut columns_of_block(block, c))
    }
}

fn mix_column(column: &mut [u8]) {
    let mut next_column = [0; 4];

    next_column[0] = g_multiply(2, column[0]) ^ g_multiply(3, column[1]) ^ column[2] ^ column[3];

    next_column[1] = column[0] ^ g_multiply(2, column[1]) ^ g_multiply(3, column[2]) ^ column[3];

    next_column[2] = column[0] ^ column[1] ^ g_multiply(2, column[2]) ^ g_multiply(3, column[3]);

    next_column[3] = g_multiply(3, column[0]) ^ column[1] ^ column[2] ^ g_multiply(2, column[3]);

    column.copy_from_slice(&next_column);
}

fn inv_mix_column(column: &mut [u8]) {
    let mut next_column = [0; 4];

    next_column[0] = g_multiply(14, column[0])
        ^ g_multiply(11, column[1])
        ^ g_multiply(13, column[2])
        ^ g_multiply(9, column[3]);

    next_column[1] = g_multiply(9, column[0])
        ^ g_multiply(14, column[1])
        ^ g_multiply(11, column[2])
        ^ g_multiply(13, column[3]);

    next_column[2] = g_multiply(13, column[0])
        ^ g_multiply(9, column[1])
        ^ g_multiply(14, column[2])
        ^ g_multiply(11, column[3]);

    next_column[3] = g_multiply(11, column[0])
        ^ g_multiply(13, column[1])
        ^ g_multiply(9, column[2])
        ^ g_multiply(14, column[3]);

    column.copy_from_slice(&next_column);
}

/// Multiplies `a` and `b` in the Galois field, GF(2^8).
fn g_multiply(a: u8, b: u8) -> u8 {
    let mut a = a;
    let mut b = b;
    let mut p = 0;

    for _ in 0..8 {
        if b & 1 != 0 {
            p ^= a;
        }

        let high_bit_set = (a & 0x80) != 0;

        a <<= 1;

        if high_bit_set {
            a ^= 0x1B;
        }
        b >>= 1;
    }

    p
}

/// Adds `expanded_key` to `block`.
fn add_round_key(block: &mut [u8], expanded_key: &[u8]) {
    for i in 0..16 {
        block[i] ^= expanded_key[i];
    }
}

#[test]
fn test_aes() {
    let code = "54776F204F6E65204E696E652054776F";
    let mut code_mut = String::from(code);

    let mut bytes = utils::hex_to_bytes(code_mut.as_mut_str());

    let key =
        AESKey::from_bytes(utils::hex_to_bytes("5468617473206D79204B756E67204675").as_slice())
            .unwrap();

    aes(&mut bytes, &key);

    let encrypted_string: String = bytes.iter().map(|v| format!("{:02X}", v)).collect();

    assert_eq!(
        encrypted_string.as_str(),
        "29C3505F571420F6402299B31A02D73A",
    );

    inv_aes(&mut bytes, &key);

    let decoded_string: String = bytes.iter().map(|v| format!("{:02X}", v)).collect();

    assert_eq!(decoded_string.as_str(), code, );
}

#[test]
fn test_key_expansion() {
    let key = utils::hex_to_bytes("5468617473206D79204B756E67204675");
    let key = AESKey::from_bytes(key.as_slice()).unwrap();

    let expanded_key = key_expansion(&key);

    let round_keys = [
        "5468617473206D79204B756E67204675",
        "E232FCF191129188B159E4E6D679A293",
        "56082007C71AB18F76435569A03AF7FA",
        "D2600DE7157ABC686339E901C3031EFB",
        "A11202C9B468BEA1D75157A01452495B",
        "B1293B3305418592D210D232C6429B69",
        "BD3DC287B87C47156A6C9527AC2E0E4E",
        "CC96ED1674EAAA031E863F24B2A8316A",
        "8E51EF21FABB4522E43D7A0656954B6C",
        "BFE2BF904559FAB2A16480B4F7F1CBD8",
        "28FDDEF86DA4244ACCC0A4FE3B316F26",
    ];

    for i in 0..expanded_key.len() {
        let expanded_key_string: String = expanded_key[i]
            .iter()
            .map(|v| format!("{:02X}", v))
            .collect();
        assert_eq!(round_keys[i], expanded_key_string);
    }
}

#[test]
fn text_mix_columns() {
    let mut column = [219, 19, 83, 69];
    mix_column(&mut column);
    assert_eq!(column, [142, 77, 161, 188]);

    inv_mix_column(&mut column);
    assert_eq!(column, [219, 19, 83, 69]);

    let mut column = [242, 10, 34, 92];
    mix_column(&mut column);
    assert_eq!(column, [159, 220, 88, 157]);

    inv_mix_column(&mut column);
    assert_eq!(column, [242, 10, 34, 92]);

    let mut column = [1, 1, 1, 1];
    mix_column(&mut column);
    assert_eq!(column, [1, 1, 1, 1]);

    inv_mix_column(&mut column);
    assert_eq!(column, [1, 1, 1, 1]);

    let mut column = [198, 198, 198, 198];
    mix_column(&mut column);
    assert_eq!(column, [198, 198, 198, 198]);

    inv_mix_column(&mut column);
    assert_eq!(column, [198, 198, 198, 198]);

    let mut column = [212, 212, 212, 213];
    mix_column(&mut column);
    assert_eq!(column, [213, 213, 215, 214]);

    inv_mix_column(&mut column);
    assert_eq!(column, [212, 212, 212, 213]);

    let mut column = [45, 38, 49, 76];
    mix_column(&mut column);
    assert_eq!(column, [77, 126, 189, 248]);

    inv_mix_column(&mut column);
    assert_eq!(column, [45, 38, 49, 76]);
}

#[test]
fn test_round() {
    let mut s = [219, 19, 83, 69, 242, 10, 34, 92, 1, 1, 1, 1, 45, 38, 49, 76];

    let sub = s;

    sub_bytes(&mut s);

    inv_sub_bytes(&mut s);

    assert_eq!(&sub, &s);
}

#[test]
fn test_sbox() {
    for i in 0..16 {
        for j in 0..16 {
            print!("{:02x} ", SBOX.0[i * 16 + j]);
        }
        println!()
    }
    println!();
    for i in 0..16 {
        for j in 0..16 {
            print!("{:02x} ", SBOX.1[i * 16 + j]);
        }
        println!()
    }
}

#[test]
fn test_encrypt_decrypt() {
    let iv = utils::random_u8s(16);
    let mode = Mode::CBC(iv);

    let mut key = AESKey::new(128).unwrap();
    key.randomize_key();

    let message = "How is it going?";
    let data = Vec::from(utils::str_to_bytes(message));

    let mut encrypted = aes_encrypt(&data, &key, &mode);

    println!("{}", utils::bytes_to_string(encrypted.as_slice()));

    let decrypt = aes_decrypt(encrypted.as_mut_slice(), &key, &mode);
    let decrypt_message = utils::bytes_to_string(decrypt.as_slice());

    println!("{}", decrypt_message);

    assert_eq!(message, decrypt_message.as_str())
}
