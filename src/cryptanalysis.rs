use crate::utils;

/// Tries to break a code with all single byte combinations then runs
/// frequency analysis to find the most plausible
pub fn break_xor_single_byte(code: &[u8]) -> Vec<(f64, String)> {
    let mut plaintexts = Vec::with_capacity(256);

    for i in 0..256 {
        plaintexts.push(utils::bytes_to_string(
            utils::xor_bytes(code, &[i as u8]).as_slice(),
        ));
    }

    let pruned_plaintexts = prune(&plaintexts);
    frequency_analysis(&pruned_plaintexts)
        .into_iter()
        .map(|(f, s)| (f, String::from(s)))
        .collect()
}

/// Removes string that a most unlikely to be readable text.
pub fn prune<S>(plaintext_possibilities: &[S]) -> Vec<&str>
where
    S: AsRef<str>,
{
    plaintext_possibilities
        .iter()
        .map(|p| p.as_ref())
        .filter(|p| {
            !p.chars()
                .any(|c| c.is_control() && !c.is_whitespace())
        })
        .collect()
}

/// Completes a frequency analysis of a
pub fn frequency_analysis<S>(plaintext_possibilities: &[S]) -> Vec<(f64, &str)>
where
    S: AsRef<str>,
{
    let mut results: Vec<_> = plaintext_possibilities
        .iter()
        .map(|text| (english_chi_squared(text.as_ref()), text.as_ref()))
        .filter(|(f, _)| !f.is_nan())
        .collect();

    results.sort_by(|(prob1, _), (prob2, _)| prob1.partial_cmp(prob2).unwrap());
    results
}

/// Gives a chi squared value for a given text according to an english frequency table.
/// The lower the value the more likely that the text is in english.
pub fn english_chi_squared(text: &str) -> f64 {
    let english_frequencies = [
        0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015, // A-G
        0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749, // H-N
        0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758, // O-U
        0.00978, 0.02360, 0.00150, 0.01974, 0.00074, 0.00001, // V-Z and Special
    ];

    let mut total_chars = 0.0;
    let mut count = [0.0; 27];
    for c in text
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| c.to_lowercase().next().unwrap())
    {
        total_chars += 1.0;
        if c >= 'a' && c <= 'z' {
            count[(c as u32 - 97) as usize] += 1.0;
        } else {
            count[26] += 1.0;
        }
    }

    let text_frequencies: Vec<_> = count.iter().map(|i| i / total_chars).collect();

    english_frequencies
        .iter()
        .zip(text_frequencies.into_iter())
        .map(|(e, t)| ((t - e) * (t - e)) / e)
        .sum()
}

/// Detects repeated blocks in an AES encryption which would indicated
/// that data is encrypted under ECB
pub fn detect_ecb(bytes: &[u8]) -> bool {
    if bytes.len() % 16 != 0 {
        println!("False {}", bytes.len());
        // If the bytes are not a multiple of 16 then it is not encrypted with AES
        return false
    }
    for i in 0..bytes.len()/16 {
        for j in i+1..bytes.len()/16 {
            for c in 0..16 {
                if bytes[i * 16 + c] != bytes[j * 16 + c] {
                    break
                }
                if c == 15 {
                    return true
                }
            }
        }
    }
    false
}