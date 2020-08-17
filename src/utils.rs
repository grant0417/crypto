/// Converts a hex string to a `Vec` of bytes
///
/// ```
/// # use crypto::utils::hex_to_bytes;
/// let bytes = hex_to_bytes("12ab9f");
/// println!("{:?}", bytes); // [18, 171, 159]
/// ```
pub fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..=i + 1], 16).unwrap())
        .collect()
}

/// Converts a byte slice to a String
///
/// ```
/// # use crypto::utils::bytes_to_string;
/// let string = bytes_to_string(&[18, 171, 159]);
/// println!("{:?}", string); // "12ab9f"
/// ```
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x?}", b)).collect()
}

/// Converts a string to bytes
pub fn str_to_bytes(str: &str) -> &[u8] {
    str.as_bytes()
}

/// Converts bytes to a `String`
pub fn bytes_to_string(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{}", *b as char))
        .collect()
}

/// Converts bytes to a `&str`
pub fn bytes_to_str(bytes: &[u8]) -> Option<&str> {
    std::str::from_utf8(&bytes).ok()
}

/// Converts a byte array to base64
pub fn bytes_to_base64(bytes: &[u8]) -> String {
    let base64_chars: Vec<&str> =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
            .split("")
            .collect();
    let mut base64_len = (bytes.len() * 4 + 2) / 3;
    if base64_len % 4 == 3 {
        base64_len += 1;
    } else if base64_len % 4 == 2 {
        base64_len += 2
    }
    let mut base64 = String::with_capacity(base64_len);

    for i in 0..(base64_len / 4) {
        base64.push_str(base64_chars[((bytes[i * 3] & 0b11111100) >> 2) as usize + 1]);

        if i * 3 + 1 < bytes.len() {
            base64.push_str(
                base64_chars[((bytes[i * 3] & 0b00000011) << 4) as usize
                    + ((bytes[i * 3 + 1] & 0b11110000) >> 4) as usize
                    + 1],
            );

            if i * 3 + 2 < bytes.len() {
                base64.push_str(
                    base64_chars[((bytes[i * 3 + 1] & 0b00001111) << 2) as usize
                        + ((bytes[i * 3 + 2] & 0b11000000) >> 6) as usize
                        + 1],
                );

                base64.push_str(base64_chars[(bytes[i * 3 + 2] & 0b00111111) as usize + 1]);
            } else {
                base64.push_str(base64_chars[((bytes[i * 3 + 1] & 0b00001111) << 2) as usize + 1]);
                base64.push('=');
            }
        } else {
            base64.push_str(base64_chars[((bytes[i * 3] & 0b00000011) << 4) as usize + 1]);
            base64.push('=');
            base64.push('=');
        }
    }

    base64
}

/// Converts base64 to a byte Vec
pub fn base64_to_bytes(base64: &str) -> Vec<u8> {
    let base64: Vec<_> = base64
        .chars()
        .filter(|c| !c.is_whitespace() && c.is_ascii())
        .collect();
    let base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes_count = base64.len() * 3 / 4;
    let mut bytes = Vec::with_capacity(bytes_count);

    for i in 0..((bytes_count) / 3) {
        match (
            (base64_chars.find(base64[i * 4])),
            (base64_chars.find(base64[i * 4 + 1])),
        ) {
            (Some(x), Some(y)) => bytes.push((x << 2) as u8 + ((y & 0b110000) >> 4) as u8),
            (Some(x), None) if x > x << 2 => bytes.push((x << 2) as u8),
            _ => {}
        }

        match (
            (base64_chars.find(base64[i * 4 + 1])),
            (base64_chars.find(base64[i * 4 + 2])),
        ) {
            (Some(x), Some(y)) => bytes.push(((x & 0xf) << 4) as u8 + ((y & 0b111100) >> 2) as u8),
            (Some(x), None) if x > x << 4 => bytes.push(((x & 0xf) << 4) as u8),
            _ => {}
        }

        match (
            (base64_chars.find(base64[i * 4 + 2])),
            (base64_chars.find(base64[i * 4 + 3])),
        ) {
            (Some(x), Some(y)) => bytes.push(((x & 0b11) << 6) as u8 + y as u8),
            (Some(x), None) if x > x << 6 => bytes.push(((x & 0b11) << 6) as u8),
            _ => {}
        }
    }

    bytes
}

/// XORs two arrays of bytes together and loops the smaller array to fit the
/// larger array
pub fn xor_bytes(b1: &[u8], b2: &[u8]) -> Vec<u8> {
    use std::cmp::Ordering;

    match b1.len().cmp(&b2.len()) {
        Ordering::Less => b1
            .iter()
            .cycle()
            .zip(b2.iter())
            .map(|(x, y)| x ^ y)
            .collect(),
        Ordering::Equal => b1
            .iter()
            .zip(b2.iter())
            .map(|(x, y)| x ^ y)
            .collect(),
        Ordering::Greater => b1
            .iter()
            .zip(b2.iter().cycle())
            .map(|(x, y)| x ^ y)
            .collect(),
    }
}

/// Computes the hamming distance of two byte arrays
pub fn hamming_distance(b1: &[u8], b2: &[u8]) -> usize {
    let mut distance = 0;
    for b in xor_bytes(b1, b2) {
        distance += b.count_ones();
    }
    distance as usize
}

/// Pads a text according to the pkcs#7 specification
pub fn pad_pkcs7(text: &mut Vec<u8>, block_size: usize) {
    let mut padding_amount = block_size - (text.len() % block_size);
    if padding_amount == 0 { padding_amount = block_size }
    for _ in 0..padding_amount {
        text.push(padding_amount as u8)
    }
}

/// Returns a slice to the data without the padding
pub fn slice_pkcs8(text: &[u8]) -> Option<&[u8]> {
    let padding_amount = *text.last().unwrap_or(&0);
    if text.iter().rev().take_while(|b| **b == padding_amount).count() == padding_amount as usize {
        Some(&text[..text.len() - padding_amount as usize])
    } else {
        None
    }
}

/// Pops off the padding off of a Vec
pub fn remove_padding_pkcs8(text: &mut Vec<u8>) -> Option<()> {
    let padding_amount = *text.last().unwrap_or(&0);
    if text.iter().rev().take_while(|b| **b == padding_amount).count() == padding_amount as usize {
        for _ in 0..padding_amount {
            text.pop();
        }
        Some(())
    } else {
        None
    }
}

/// Creates a Vec of random u8s with length `len`
pub fn random_u8s(len: usize) -> Vec<u8> {
    use rand::prelude::*;
    let mut rng = thread_rng();
    let bytes: Vec<u8> = (0..len).map(|_| rng.gen::<u8>()).collect();
    bytes
}

/// Creates a Vec of random u32s with length `len`
pub fn random_u32s(len: usize) -> Vec<u32> {
    use rand::prelude::*;
    let mut rng = thread_rng();
    let bytes: Vec<u32> = (0..len).map(|_| rng.gen::<u32>()).collect();
    bytes
}

/// Generate a random bool
pub fn random_bool() -> bool {
    use rand::prelude::*;
    random()
}

/// Generates a random usize in the range
pub fn random_range(range: std::ops::Range<usize>) -> usize {
    use rand::prelude::*;
    let mut rng = thread_rng();
    rng.gen_range(range.start, range.end)
}

#[test]
fn text_to_base64_test() {
    assert_eq!(
        bytes_to_base64(str_to_bytes("any carnal pleasur")),
        "YW55IGNhcm5hbCBwbGVhc3Vy"
    );
    assert_eq!(
        bytes_to_base64(str_to_bytes("any carnal pleasure.")),
        "YW55IGNhcm5hbCBwbGVhc3VyZS4="
    );
    assert_eq!(
        bytes_to_base64(str_to_bytes("any carnal pleasure")),
        "YW55IGNhcm5hbCBwbGVhc3VyZQ=="
    );

    assert_eq!(
        bytes_to_base64(str_to_bytes("any carnal pleasu")),
        "YW55IGNhcm5hbCBwbGVhc3U="
    );
    assert_eq!(
        bytes_to_base64(str_to_bytes("any carnal pleas")),
        "YW55IGNhcm5hbCBwbGVhcw=="
    );
}

#[test]
fn base64_to_text_test() {
    assert_eq!(
        "any carnal pleasur",
        bytes_to_string(base64_to_bytes("YW55IGNhcm5hbCBwbGVhc3Vy").as_slice())
    );
    assert_eq!(
        "any carnal pleasure",
        bytes_to_string(base64_to_bytes("YW55IGNhcm5hbCBwbGVhc3VyZQ==").as_slice())
    );
    assert_eq!(
        "any carnal pleasure.",
        bytes_to_string(base64_to_bytes("YW55IGNhcm5hbCBwbGVhc3VyZS4=").as_slice())
    );
}

#[test]
fn hex_to_hex() {
    let hex = "12acb4c280cdef";
    let bytes = hex_to_bytes(hex);
    let hex_trans = bytes_to_hex(bytes.as_slice());
    assert_eq!(hex, hex_trans.as_str())
}

#[test]
fn string_to_bytes() {
    let string = "Hello there";
    assert_eq!(
        vec![72, 101, 108, 108, 111, 32, 116, 104, 101, 114, 101],
        str_to_bytes(string)
    )
}

#[test]
fn hamming_test() {
    let s1 = "this is a test";
    let s2 = "wokka wokka!!!";
    let distance = hamming_distance(str_to_bytes(s1), str_to_bytes(s2));
    assert_eq!(distance, 37)
}
