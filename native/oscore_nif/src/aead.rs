//! RFC 8613 §5.2 (AEAD nonce), §5.4 (AAD), and AES-CCM-16-64-128 encrypt/decrypt.

use crate::context::AEAD_NONCE_LEN;
use aes::Aes128;
use ccm::aead::generic_array::GenericArray;
use ccm::aead::{Aead, Payload};
use ccm::{consts::U13, consts::U8, Ccm, KeyInit};
use ciborium::Value;

type AesCcm16_64_128 = Ccm<Aes128, U8, U13>;

/// RFC 8613 §5.2: build the AEAD nonce from the Sender ID of the endpoint that
/// generated the Partial IV, the Partial IV itself, and the Common IV.
pub fn compute_nonce(
    id_piv: &[u8],
    partial_iv: &[u8],
    common_iv: &[u8; AEAD_NONCE_LEN],
) -> [u8; AEAD_NONCE_LEN] {
    let id_field_len = AEAD_NONCE_LEN - 6;
    assert!(
        id_piv.len() <= id_field_len,
        "Sender ID longer than the nonce allows"
    );
    assert!(partial_iv.len() <= 5, "Partial IV longer than 5 bytes");

    let mut buf = [0u8; AEAD_NONCE_LEN];
    buf[0] = id_piv.len() as u8;

    let id_start = 1 + (id_field_len - id_piv.len());
    buf[id_start..1 + id_field_len].copy_from_slice(id_piv);

    let piv_start = AEAD_NONCE_LEN - partial_iv.len();
    buf[piv_start..].copy_from_slice(partial_iv);

    for i in 0..AEAD_NONCE_LEN {
        buf[i] ^= common_iv[i];
    }
    buf
}

/// RFC 8613 §5.4: `aad_array = [oscore_version, [alg_aead], request_kid, request_piv, options]`.
fn build_aad_array(request_kid: &[u8], request_piv: &[u8], class_i_options: &[u8]) -> Vec<u8> {
    let value = Value::Array(vec![
        Value::Integer(1.into()),
        Value::Array(vec![Value::Integer(
            crate::context::ALG_AEAD_AES_CCM_16_64_128.into(),
        )]),
        Value::Bytes(request_kid.to_vec()),
        Value::Bytes(request_piv.to_vec()),
        Value::Bytes(class_i_options.to_vec()),
    ]);
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&value, &mut buf).expect("aad_array is always serializable");
    buf
}

/// RFC 8613 §5.4 / RFC 8152 §5.3: `AAD = Enc_structure = ["Encrypt0", h'', external_aad]`.
pub fn build_aad(request_kid: &[u8], request_piv: &[u8], class_i_options: &[u8]) -> Vec<u8> {
    let aad_array = build_aad_array(request_kid, request_piv, class_i_options);
    let value = Value::Array(vec![
        Value::Text("Encrypt0".to_string()),
        Value::Bytes(vec![]),
        Value::Bytes(aad_array),
    ]);
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&value, &mut buf).expect("AAD is always serializable");
    buf
}

pub fn encrypt(
    key: &[u8; 16],
    nonce: &[u8; AEAD_NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    let cipher = AesCcm16_64_128::new(GenericArray::from_slice(key));
    cipher
        .encrypt(
            GenericArray::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("CCM encryption with valid parameters cannot fail")
}

pub fn decrypt(
    key: &[u8; 16],
    nonce: &[u8; AEAD_NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, ()> {
    let cipher = AesCcm16_64_128::new(GenericArray::from_slice(key));
    cipher
        .decrypt(
            GenericArray::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| ())
}

/// RFC 8613 §8.1 step 3 / §8.3 step 3: minimal big-endian encoding of the Sender
/// Sequence Number, with 0 encoded as a single zero byte (the Partial IV is
/// always present in a freshly generated nonce, even for sequence number 0).
pub fn encode_partial_iv(seq: u64) -> Option<Vec<u8>> {
    if seq == 0 {
        return Some(vec![0]);
    }
    let bytes = seq.to_be_bytes();
    let first_nonzero = bytes.iter().position(|&b| b != 0)?;
    let encoded = &bytes[first_nonzero..];
    if encoded.len() > 5 {
        None
    } else {
        Some(encoded.to_vec())
    }
}
