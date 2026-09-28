//! AES-128, the block cipher every `LoRaWAN` key drives, and the two uses the
//! specification makes of it: CMAC (RFC 4493) for the MIC, and the counter
//! blocks that encrypt the `FRMPayload`. The cipher is `RustCrypto`'s `aes`
//! crate — the one the estate's SSH and Kerberos take — constant-time on
//! every target, and CMAC is its `cmac` crate; what is here is how
//! `LoRaWAN` uses them.

use aes::Aes128;
use aes::cipher::{Array, BlockCipherEncrypt, KeyInit};
use cmac::{Cmac, Mac};

/// One block, and one key: sixteen bytes.
pub const BLOCK: usize = 16;

/// `block` encrypted under `key`: one AES-128 block.
#[must_use]
pub fn encrypt(key: &[u8; BLOCK], block: &[u8; BLOCK]) -> [u8; BLOCK] {
    let mut state = Array::from(*block);
    Aes128::new(&Array::from(*key)).encrypt_block(&mut state);
    state.into()
}

/// The CMAC of `message` under `key`, ready to finish or to check.
fn mac(key: &[u8; BLOCK], message: &[u8]) -> Cmac<Aes128> {
    let mut mac = <Cmac<Aes128> as KeyInit>::new(&Array::from(*key));
    mac.update(message);
    mac
}

/// AES-CMAC of `message` under `key`, RFC 4493.
#[must_use]
pub fn cmac(key: &[u8; BLOCK], message: &[u8]) -> [u8; BLOCK] {
    mac(key, message).finalize().into_bytes().into()
}

/// Whether `mic` is the leading bytes of `message`'s CMAC under `key`,
/// compared in constant time: the MIC a frame carries is four of them.
#[must_use]
pub fn verifies(key: &[u8; BLOCK], message: &[u8], mic: &[u8]) -> bool {
    mac(key, message).verify_truncated_left(mic).is_ok()
}

/// `bytes` under the key stream of counter blocks `first` onward, each
/// block `first` with its last byte counting from one: `LoRaWAN`'s `FRMPayload`
/// encryption, which is its own inverse.
#[must_use]
pub fn counter(key: &[u8; BLOCK], first: &[u8; BLOCK], bytes: &[u8]) -> Vec<u8> {
    let cipher = Aes128::new(&Array::from(*key));
    let mut out = Vec::with_capacity(bytes.len());
    for (index, chunk) in bytes.chunks(BLOCK).enumerate() {
        let mut block = Array::from(*first);
        block[BLOCK - 1] = u8::try_from(index + 1).unwrap_or(u8::MAX);
        cipher.encrypt_block(&mut block);
        out.extend(chunk.iter().zip(block.iter()).map(|(b, s)| b ^ s));
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
    fn a_truncated_mic_verifies_only_where_it_is_the_macs_lead() {
        let message = b"a frame";
        let full = cmac(&KEY, message);
        assert!(verifies(&KEY, message, &full[..4]));
        let mut wrong = full;
        wrong[3] ^= 1;
        assert!(!verifies(&KEY, message, &wrong[..4]));
        assert!(!verifies(&KEY, b"another frame", &full[..4]));
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
