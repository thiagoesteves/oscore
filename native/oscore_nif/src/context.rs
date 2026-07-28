//! RFC 8613 §3.2: Security Context derivation (AES-CCM-16-64-128 / HKDF-SHA-256).

use crate::replay::ReplayWindow;
use ciborium::Value;
use hkdf::Hkdf;
use sha2::Sha256;

pub const AEAD_KEY_LEN: usize = 16;
pub const AEAD_NONCE_LEN: usize = 13;
pub const ALG_AEAD_AES_CCM_16_64_128: i64 = 10;

/// RFC 8613 §3.3: the maximum Sender/Recipient ID length is the AEAD nonce
/// length minus 6, i.e. 7 bytes for AES-CCM-16-64-128. A longer ID cannot fit
/// in the nonce and is rejected at context-derivation time.
pub const MAX_ID_LEN: usize = AEAD_NONCE_LEN - 6;

pub struct DerivedContext {
    pub sender_key: [u8; AEAD_KEY_LEN],
    pub recipient_key: [u8; AEAD_KEY_LEN],
    pub common_iv: [u8; AEAD_NONCE_LEN],
}

/// The mutable, per-pair Security Context: derived keys/IV plus the Sender
/// Sequence Number and Recipient replay window (§3.1, §3.2, §7.4).
pub struct ContextState {
    pub sender_id: Vec<u8>,
    pub recipient_id: Vec<u8>,
    pub id_context: Option<Vec<u8>>,
    pub sender_key: [u8; AEAD_KEY_LEN],
    pub recipient_key: [u8; AEAD_KEY_LEN],
    pub common_iv: [u8; AEAD_NONCE_LEN],
    pub sender_seq: u64,
    pub replay: ReplayWindow,
}

/// Whether both IDs fit the AEAD nonce (RFC 8613 §3.3). Enforced at
/// context-derivation time so a too-long ID fails cleanly instead of panicking
/// later when the nonce is assembled.
pub fn ids_within_nonce_limit(sender_id: &[u8], recipient_id: &[u8]) -> bool {
    sender_id.len() <= MAX_ID_LEN && recipient_id.len() <= MAX_ID_LEN
}

impl ContextState {
    pub fn new(
        master_secret: &[u8],
        master_salt: &[u8],
        sender_id: Vec<u8>,
        recipient_id: Vec<u8>,
        id_context: Option<&[u8]>,
    ) -> Self {
        let derived = derive(
            master_secret,
            master_salt,
            &sender_id,
            &recipient_id,
            id_context,
        );
        Self {
            sender_id,
            recipient_id,
            id_context: id_context.map(|c| c.to_vec()),
            sender_key: derived.sender_key,
            recipient_key: derived.recipient_key,
            common_iv: derived.common_iv,
            sender_seq: 0,
            replay: ReplayWindow::new(),
        }
    }
}

fn build_info(id: &[u8], id_context: Option<&[u8]>, alg_aead: i64, typ: &str, l: usize) -> Vec<u8> {
    let id_context_value = match id_context {
        Some(ctx) => Value::Bytes(ctx.to_vec()),
        None => Value::Null,
    };

    let value = Value::Array(vec![
        Value::Bytes(id.to_vec()),
        id_context_value,
        Value::Integer(alg_aead.into()),
        Value::Text(typ.to_string()),
        Value::Integer((l as i64).into()),
    ]);

    let mut buf = Vec::new();
    ciborium::ser::into_writer(&value, &mut buf).expect("info is always serializable");
    buf
}

fn hkdf_expand(salt: &[u8], ikm: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = vec![0u8; len];
    hk.expand(info, &mut okm)
        .expect("requested length is within HKDF-SHA-256's valid output range");
    okm
}

/// Derives the Sender Key, Recipient Key, and Common IV from the Common Context
/// input parameters, per RFC 8613 §3.2.1.
pub fn derive(
    master_secret: &[u8],
    master_salt: &[u8],
    sender_id: &[u8],
    recipient_id: &[u8],
    id_context: Option<&[u8]>,
) -> DerivedContext {
    let alg = ALG_AEAD_AES_CCM_16_64_128;

    let sender_info = build_info(sender_id, id_context, alg, "Key", AEAD_KEY_LEN);
    let recipient_info = build_info(recipient_id, id_context, alg, "Key", AEAD_KEY_LEN);
    let iv_info = build_info(&[], id_context, alg, "IV", AEAD_NONCE_LEN);

    let sender_key = hkdf_expand(master_salt, master_secret, &sender_info, AEAD_KEY_LEN);
    let recipient_key = hkdf_expand(master_salt, master_secret, &recipient_info, AEAD_KEY_LEN);
    let common_iv = hkdf_expand(master_salt, master_secret, &iv_info, AEAD_NONCE_LEN);

    DerivedContext {
        sender_key: sender_key.try_into().expect("AEAD_KEY_LEN bytes"),
        recipient_key: recipient_key.try_into().expect("AEAD_KEY_LEN bytes"),
        common_iv: common_iv.try_into().expect("AEAD_NONCE_LEN bytes"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_within_nonce_limit_enforces_max_id_len() {
        assert!(ids_within_nonce_limit(
            &[0u8; MAX_ID_LEN],
            &[0u8; MAX_ID_LEN]
        ));
        assert!(ids_within_nonce_limit(&[], &[]));
        assert!(!ids_within_nonce_limit(&[0u8; MAX_ID_LEN + 1], &[]));
        assert!(!ids_within_nonce_limit(&[], &[0u8; MAX_ID_LEN + 1]));
    }
}
