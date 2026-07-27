//! RFC 8613 §5.3 (plaintext), §8.1-8.4 (protect/verify request/response).

use crate::aead;
use crate::context::{ContextState, AEAD_NONCE_LEN};
use crate::option::{self, OscoreOption};
use crate::replay::ReplayError;

/// The (kid, Partial IV, nonce) of a request, needed to protect/verify its
/// matching response per §5.4 and §8.3/§8.4.
#[derive(Debug, Clone)]
pub struct RequestEcho {
    pub kid: Vec<u8>,
    pub piv: Vec<u8>,
    pub nonce: [u8; AEAD_NONCE_LEN],
}

#[derive(Debug, Clone)]
pub struct Protected {
    pub oscore_option: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

#[derive(Debug)]
pub enum ProtocolError {
    SequenceNumberExhausted,
    MalformedOption,
    MalformedPlaintext,
    DecryptionFailed,
    UnknownKid,
    Replayed,
    TooOld,
}

fn build_plaintext(code: u8, inner_options: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut buf = vec![code];
    buf.extend_from_slice(inner_options);
    if !payload.is_empty() {
        buf.push(0xff);
        buf.extend_from_slice(payload);
    }
    buf
}

/// Walks CoAP option TLV encoding (RFC 7252 §3.1) to find the length of the
/// inner-option sequence at the start of `data`, stopping at either the 0xff
/// payload marker or the end of `data`. A delta/length nibble of 15 can never
/// occur in a real option header, which is what makes the payload marker
/// unambiguous even though option values may themselves contain 0xff bytes.
fn coap_options_len(data: &[u8]) -> Result<usize, ProtocolError> {
    let mut pos = 0usize;
    loop {
        if pos >= data.len() {
            return Ok(pos);
        }
        if data[pos] == 0xff {
            return Ok(pos);
        }

        let header = data[pos];
        let delta_nibble = header >> 4;
        let length_nibble = header & 0x0f;
        if delta_nibble == 0x0f || length_nibble == 0x0f {
            return Err(ProtocolError::MalformedPlaintext);
        }
        pos += 1;

        match delta_nibble {
            13 => {
                if pos >= data.len() {
                    return Err(ProtocolError::MalformedPlaintext);
                }
                pos += 1;
            }
            14 => {
                if pos + 2 > data.len() {
                    return Err(ProtocolError::MalformedPlaintext);
                }
                pos += 2;
            }
            _ => {}
        }

        let length = match length_nibble {
            0..=12 => length_nibble as usize,
            13 => {
                if pos >= data.len() {
                    return Err(ProtocolError::MalformedPlaintext);
                }
                let v = data[pos] as usize + 13;
                pos += 1;
                v
            }
            14 => {
                if pos + 2 > data.len() {
                    return Err(ProtocolError::MalformedPlaintext);
                }
                let v = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize + 269;
                pos += 2;
                v
            }
            _ => unreachable!(),
        };

        if pos + length > data.len() {
            return Err(ProtocolError::MalformedPlaintext);
        }
        pos += length;
    }
}

fn split_plaintext(plaintext: &[u8]) -> Result<(u8, Vec<u8>, Vec<u8>), ProtocolError> {
    if plaintext.is_empty() {
        return Err(ProtocolError::MalformedPlaintext);
    }
    let code = plaintext[0];
    let rest = &plaintext[1..];
    let opts_len = coap_options_len(rest)?;
    let inner_options = rest[..opts_len].to_vec();
    let payload = if opts_len < rest.len() {
        rest[opts_len + 1..].to_vec()
    } else {
        vec![]
    };
    Ok((code, inner_options, payload))
}

fn be_bytes_to_u64(bytes: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    buf[8 - bytes.len()..].copy_from_slice(bytes);
    u64::from_be_bytes(buf)
}

/// RFC 8613 §8.1: protect an outgoing CoAP request.
pub fn protect_request(
    ctx: &mut ContextState,
    code: u8,
    inner_options: &[u8],
    payload: &[u8],
) -> Result<(Protected, RequestEcho), ProtocolError> {
    let piv =
        aead::encode_partial_iv(ctx.sender_seq).ok_or(ProtocolError::SequenceNumberExhausted)?;
    ctx.sender_seq += 1;

    let nonce = aead::compute_nonce(&ctx.sender_id, &piv, &ctx.common_iv);
    let aad = aead::build_aad(&ctx.sender_id, &piv, &[]);
    let plaintext = build_plaintext(code, inner_options, payload);
    let ciphertext = aead::encrypt(&ctx.sender_key, &nonce, &aad, &plaintext);

    let oscore_option = option::encode(&OscoreOption {
        partial_iv: piv.clone(),
        kid_context: None,
        kid: Some(ctx.sender_id.clone()),
    });

    Ok((
        Protected {
            oscore_option,
            ciphertext,
        },
        RequestEcho {
            kid: ctx.sender_id.clone(),
            piv,
            nonce,
        },
    ))
}

/// RFC 8613 §8.2: verify an incoming CoAP request.
pub fn unprotect_request(
    ctx: &mut ContextState,
    oscore_option: &[u8],
    ciphertext: &[u8],
    class_i_options: &[u8],
) -> Result<(u8, Vec<u8>, Vec<u8>, RequestEcho), ProtocolError> {
    let opt = option::decode(oscore_option).map_err(|_| ProtocolError::MalformedOption)?;
    if opt.partial_iv.is_empty() {
        return Err(ProtocolError::MalformedOption);
    }
    let kid = opt.kid.unwrap_or_default();
    if kid != ctx.recipient_id {
        return Err(ProtocolError::UnknownKid);
    }

    let seq = be_bytes_to_u64(&opt.partial_iv);
    let nonce = aead::compute_nonce(&ctx.recipient_id, &opt.partial_iv, &ctx.common_iv);
    let aad = aead::build_aad(&kid, &opt.partial_iv, class_i_options);
    let plaintext = aead::decrypt(&ctx.recipient_key, &nonce, &aad, ciphertext)
        .map_err(|_| ProtocolError::DecryptionFailed)?;

    ctx.replay.check_and_update(seq).map_err(|e| match e {
        ReplayError::Replayed => ProtocolError::Replayed,
        ReplayError::TooOld => ProtocolError::TooOld,
    })?;

    let (plain_code, inner_options, payload) = split_plaintext(&plaintext)?;
    let echo = RequestEcho {
        kid,
        piv: opt.partial_iv,
        nonce,
    };
    Ok((plain_code, inner_options, payload, echo))
}

/// RFC 8613 §8.3: protect an outgoing CoAP response. `reuse_request_nonce`
/// selects between the two RFC-compliant modes: reusing the request's nonce
/// (typical for a single response, no Partial IV sent) or generating a fresh
/// one from the Sender Sequence Number (required for Observe notifications).
pub fn protect_response(
    ctx: &mut ContextState,
    code: u8,
    inner_options: &[u8],
    payload: &[u8],
    request_echo: &RequestEcho,
    reuse_request_nonce: bool,
) -> Result<Protected, ProtocolError> {
    let (nonce, piv_for_option) = if reuse_request_nonce {
        (request_echo.nonce, None)
    } else {
        let piv = aead::encode_partial_iv(ctx.sender_seq)
            .ok_or(ProtocolError::SequenceNumberExhausted)?;
        ctx.sender_seq += 1;
        let nonce = aead::compute_nonce(&ctx.sender_id, &piv, &ctx.common_iv);
        (nonce, Some(piv))
    };

    let aad = aead::build_aad(&request_echo.kid, &request_echo.piv, &[]);
    let plaintext = build_plaintext(code, inner_options, payload);
    let ciphertext = aead::encrypt(&ctx.sender_key, &nonce, &aad, &plaintext);

    let oscore_option = option::encode(&OscoreOption {
        partial_iv: piv_for_option.unwrap_or_default(),
        kid_context: None,
        kid: None,
    });

    Ok(Protected {
        oscore_option,
        ciphertext,
    })
}

/// RFC 8613 §8.4: verify an incoming CoAP response.
pub fn unprotect_response(
    ctx: &ContextState,
    oscore_option: &[u8],
    ciphertext: &[u8],
    class_i_options: &[u8],
    request_echo: &RequestEcho,
) -> Result<(u8, Vec<u8>, Vec<u8>), ProtocolError> {
    let opt = option::decode(oscore_option).map_err(|_| ProtocolError::MalformedOption)?;

    let nonce = if opt.partial_iv.is_empty() {
        request_echo.nonce
    } else {
        aead::compute_nonce(&ctx.recipient_id, &opt.partial_iv, &ctx.common_iv)
    };

    let aad = aead::build_aad(&request_echo.kid, &request_echo.piv, class_i_options);
    let plaintext = aead::decrypt(&ctx.recipient_key, &nonce, &aad, ciphertext)
        .map_err(|_| ProtocolError::DecryptionFailed)?;

    split_plaintext(&plaintext)
}
