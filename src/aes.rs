//! AES-128, the block cipher every `LoRaWAN` key drives, and the two uses the
//! specification makes of it: CMAC (RFC 4493) for the MIC, and the counter
//! blocks that encrypt the `FRMPayload`. Encryption only — CMAC and the
//! counter mode never decrypt a block — so the inverse cipher is not here.
//!
//! Written out rather than taken from a crate because the estate prefers
//! the standard library for framing, and a cipher of a hundred lines with
//! its test vectors is closer to framing than to a dependency.

/// One block, and one key: sixteen bytes.
pub const BLOCK: usize = 16;

#[rustfmt::skip]
const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

/// Multiplication by two in GF(2^8) with the AES polynomial.
const fn xtime(byte: u8) -> u8 {
    (byte << 1) ^ if byte & 0x80 != 0 { 0x1b } else { 0 }
}

/// The eleven round keys of AES-128.
fn expand(key: &[u8; BLOCK]) -> [[u8; BLOCK]; 11] {
    let mut round_keys = [[0u8; BLOCK]; 11];
    round_keys[0] = *key;
    let mut rcon = 1u8;
    for round in 1..11 {
        let previous = round_keys[round - 1];
        let mut word = [previous[13], previous[14], previous[15], previous[12]];
        for byte in &mut word {
            *byte = SBOX[usize::from(*byte)];
        }
        word[0] ^= rcon;
        rcon = xtime(rcon);
        let mut next = [0u8; BLOCK];
        for at in 0..BLOCK {
            let carried = if at < 4 { word[at] } else { next[at - 4] };
            next[at] = previous[at] ^ carried;
        }
        round_keys[round] = next;
    }
    round_keys
}

fn mix_column(column: &mut [u8]) {
    let (a, b, c, d) = (column[0], column[1], column[2], column[3]);
    let all = a ^ b ^ c ^ d;
    column[0] ^= all ^ xtime(a ^ b);
    column[1] ^= all ^ xtime(b ^ c);
    column[2] ^= all ^ xtime(c ^ d);
    column[3] ^= all ^ xtime(d ^ a);
}

/// One block under `key`.
#[must_use]
pub fn encrypt(key: &[u8; BLOCK], block: &[u8; BLOCK]) -> [u8; BLOCK] {
    let round_keys = expand(key);
    let mut state = *block;
    for (byte, k) in state.iter_mut().zip(&round_keys[0]) {
        *byte ^= k;
    }
    for (round, round_key) in round_keys.iter().enumerate().skip(1) {
        for byte in &mut state {
            *byte = SBOX[usize::from(*byte)];
        }
        // Shift rows: row r of the column-major state rotates left by r.
        let shifted = state;
        for column in 0..4 {
            for row in 0..4 {
                state[column * 4 + row] = shifted[((column + row) % 4) * 4 + row];
            }
        }
        if round != 10 {
            for column in state.as_chunks_mut::<4>().0 {
                mix_column(column);
            }
        }
        for (byte, k) in state.iter_mut().zip(round_key) {
            *byte ^= k;
        }
    }
    state
}

/// The CMAC subkey step: shift left by one and reduce by the polynomial.
fn double(block: &[u8; BLOCK]) -> [u8; BLOCK] {
    let mut out = [0u8; BLOCK];
    let mut carry = 0;
    for at in (0..BLOCK).rev() {
        out[at] = (block[at] << 1) | carry;
        carry = block[at] >> 7;
    }
    if block[0] & 0x80 != 0 {
        out[BLOCK - 1] ^= 0x87;
    }
    out
}

/// AES-CMAC of `message` under `key`, RFC 4493.
#[must_use]
pub fn cmac(key: &[u8; BLOCK], message: &[u8]) -> [u8; BLOCK] {
    let k1 = double(&encrypt(key, &[0; BLOCK]));
    let k2 = double(&k1);
    let whole = message.len().div_ceil(BLOCK).max(1);
    let mut mac = [0u8; BLOCK];
    for (index, chunk) in message
        .chunks(BLOCK)
        .chain(if message.is_empty() {
            Some(&[][..])
        } else {
            None
        })
        .enumerate()
    {
        let mut block = [0u8; BLOCK];
        block[..chunk.len()].copy_from_slice(chunk);
        if index + 1 == whole {
            let subkey = if chunk.len() == BLOCK { k1 } else { k2 };
            if chunk.len() < BLOCK {
                block[chunk.len()] = 0x80;
            }
            for (byte, k) in block.iter_mut().zip(&subkey) {
                *byte ^= k;
            }
        }
        for (byte, m) in block.iter_mut().zip(&mac) {
            *byte ^= m;
        }
        mac = encrypt(key, &block);
    }
    mac
}

/// `bytes` under the key stream of counter blocks `first` onward, each
/// block `first` with its last byte counting from one: `LoRaWAN`'s `FRMPayload`
/// encryption, which is its own inverse.
#[must_use]
pub fn counter(key: &[u8; BLOCK], first: &[u8; BLOCK], bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    for (index, chunk) in bytes.chunks(BLOCK).enumerate() {
        let mut block = *first;
        block[BLOCK - 1] = u8::try_from(index + 1).unwrap_or(u8::MAX);
        let stream = encrypt(key, &block);
        out.extend(chunk.iter().zip(&stream).map(|(b, s)| b ^ s));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; BLOCK] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c,
    ];

    #[test]
    fn the_fips_197_vector_encrypts_as_the_standard_says() {
        let key: [u8; BLOCK] = std::array::from_fn(|i| u8::try_from(i).unwrap_or(0));
        let block: [u8; BLOCK] = std::array::from_fn(|i| u8::try_from(i * 0x11).unwrap_or(0));
        assert_eq!(
            encrypt(&key, &block),
            [
                0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4,
                0xc5, 0x5a
            ]
        );
    }

    #[test]
    fn the_rfc_4493_vectors_mac_as_the_rfc_says() {
        assert_eq!(
            cmac(&KEY, &[]),
            [
                0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28, 0x7f, 0xa3, 0x7d, 0x12, 0x9b, 0x75,
                0x67, 0x46
            ]
        );
        let sixteen = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a,
        ];
        assert_eq!(
            cmac(&KEY, &sixteen),
            [
                0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44, 0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a,
                0x28, 0x7c
            ]
        );
        let forty = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac,
            0x45, 0xaf, 0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
        ];
        assert_eq!(
            cmac(&KEY, &forty),
            [
                0xdf, 0xa6, 0x67, 0x47, 0xde, 0x9a, 0xe6, 0x30, 0x30, 0xca, 0x32, 0x61, 0x14, 0x97,
                0xc8, 0x27
            ]
        );
    }

    #[test]
    fn the_counter_stream_is_its_own_inverse() {
        let first = [1, 0, 0, 0, 0, 0, 0x12, 0x34, 0x56, 0x78, 7, 0, 0, 0, 0, 0];
        let plain: Vec<u8> = (0..50).collect();
        let cipher = counter(&KEY, &first, &plain);
        assert_ne!(cipher, plain);
        assert_eq!(counter(&KEY, &first, &cipher), plain);
        assert!(counter(&KEY, &first, &[]).is_empty());
    }
}
