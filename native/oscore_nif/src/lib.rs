mod aead;
mod context;
mod option;
mod protocol;
mod replay;

use context::{ContextState, AEAD_NONCE_LEN};
use rustler::{Atom, Binary, Env, OwnedBinary, ResourceArc};
use std::sync::Mutex;

pub struct ContextResource(Mutex<ContextState>);

#[rustler::resource_impl]
impl rustler::Resource for ContextResource {}

mod atoms {
    rustler::atoms! {
        sequence_number_exhausted,
        malformed_option,
        malformed_plaintext,
        decryption_failed,
        unknown_kid,
        unknown_id_context,
        replayed,
        too_old,
        id_too_long,
    }
}

fn protocol_error_to_atom(err: protocol::ProtocolError) -> Atom {
    use protocol::ProtocolError::*;
    match err {
        SequenceNumberExhausted => atoms::sequence_number_exhausted(),
        MalformedOption => atoms::malformed_option(),
        MalformedPlaintext => atoms::malformed_plaintext(),
        DecryptionFailed => atoms::decryption_failed(),
        UnknownKid => atoms::unknown_kid(),
        UnknownIdContext => atoms::unknown_id_context(),
        Replayed => atoms::replayed(),
        TooOld => atoms::too_old(),
    }
}

fn to_binary<'a>(env: Env<'a>, bytes: &[u8]) -> Binary<'a> {
    let mut owned = OwnedBinary::new(bytes.len()).expect("allocation failed");
    owned.as_mut_slice().copy_from_slice(bytes);
    Binary::from_owned(owned, env)
}

fn nonce_from_binary(bin: &Binary) -> Result<[u8; AEAD_NONCE_LEN], Atom> {
    bin.as_slice()
        .try_into()
        .map_err(|_| atoms::malformed_option())
}

#[rustler::nif]
fn derive_context<'a>(
    master_secret: Binary<'a>,
    master_salt: Binary<'a>,
    sender_id: Binary<'a>,
    recipient_id: Binary<'a>,
    id_context: Option<Binary<'a>>,
    sender_seq: u64,
) -> Result<ResourceArc<ContextResource>, Atom> {
    if !context::ids_within_nonce_limit(sender_id.as_slice(), recipient_id.as_slice()) {
        return Err(atoms::id_too_long());
    }

    let mut state = ContextState::new(
        master_secret.as_slice(),
        master_salt.as_slice(),
        sender_id.as_slice().to_vec(),
        recipient_id.as_slice().to_vec(),
        id_context.as_ref().map(Binary::as_slice),
    );
    state.sender_seq = sender_seq;
    Ok(ResourceArc::new(ContextResource(Mutex::new(state))))
}

/// Returns the next Sender Sequence Number this context will use. Callers can
/// persist it and restore it via `derive_context`'s `sender_seq` argument to
/// avoid AEAD nonce reuse across restarts (RFC 8613 Appendix B.1).
#[rustler::nif]
fn sender_seq(ctx: ResourceArc<ContextResource>) -> u64 {
    ctx.0.lock().unwrap().sender_seq
}

#[allow(clippy::type_complexity)]
#[rustler::nif]
fn protect_request<'a>(
    env: Env<'a>,
    ctx: ResourceArc<ContextResource>,
    code: u8,
    inner_options: Binary<'a>,
    payload: Binary<'a>,
) -> Result<(Binary<'a>, Binary<'a>, Binary<'a>, Binary<'a>, Binary<'a>), Atom> {
    let mut state = ctx.0.lock().unwrap();
    let (protected, echo) = protocol::protect_request(
        &mut state,
        code,
        inner_options.as_slice(),
        payload.as_slice(),
    )
    .map_err(protocol_error_to_atom)?;
    Ok((
        to_binary(env, &protected.oscore_option),
        to_binary(env, &protected.ciphertext),
        to_binary(env, &echo.kid),
        to_binary(env, &echo.piv),
        to_binary(env, &echo.nonce),
    ))
}

#[allow(clippy::type_complexity)]
#[rustler::nif]
fn unprotect_request<'a>(
    env: Env<'a>,
    ctx: ResourceArc<ContextResource>,
    oscore_option: Binary<'a>,
    ciphertext: Binary<'a>,
    class_i_options: Binary<'a>,
) -> Result<
    (
        u8,
        Binary<'a>,
        Binary<'a>,
        Binary<'a>,
        Binary<'a>,
        Binary<'a>,
    ),
    Atom,
> {
    let mut state = ctx.0.lock().unwrap();
    let (plain_code, inner_options, payload, echo) = protocol::unprotect_request(
        &mut state,
        oscore_option.as_slice(),
        ciphertext.as_slice(),
        class_i_options.as_slice(),
    )
    .map_err(protocol_error_to_atom)?;
    Ok((
        plain_code,
        to_binary(env, &inner_options),
        to_binary(env, &payload),
        to_binary(env, &echo.kid),
        to_binary(env, &echo.piv),
        to_binary(env, &echo.nonce),
    ))
}

#[allow(clippy::too_many_arguments)]
#[rustler::nif]
fn protect_response<'a>(
    env: Env<'a>,
    ctx: ResourceArc<ContextResource>,
    code: u8,
    inner_options: Binary<'a>,
    payload: Binary<'a>,
    request_kid: Binary<'a>,
    request_piv: Binary<'a>,
    request_nonce: Binary<'a>,
    reuse_request_nonce: bool,
) -> Result<(Binary<'a>, Binary<'a>), Atom> {
    let mut state = ctx.0.lock().unwrap();
    let echo = protocol::RequestEcho {
        kid: request_kid.as_slice().to_vec(),
        piv: request_piv.as_slice().to_vec(),
        nonce: nonce_from_binary(&request_nonce)?,
    };
    let protected = protocol::protect_response(
        &mut state,
        code,
        inner_options.as_slice(),
        payload.as_slice(),
        &echo,
        reuse_request_nonce,
    )
    .map_err(protocol_error_to_atom)?;
    Ok((
        to_binary(env, &protected.oscore_option),
        to_binary(env, &protected.ciphertext),
    ))
}

#[allow(clippy::too_many_arguments)]
#[rustler::nif]
fn unprotect_response<'a>(
    env: Env<'a>,
    ctx: ResourceArc<ContextResource>,
    oscore_option: Binary<'a>,
    ciphertext: Binary<'a>,
    class_i_options: Binary<'a>,
    request_kid: Binary<'a>,
    request_piv: Binary<'a>,
    request_nonce: Binary<'a>,
) -> Result<(u8, Binary<'a>, Binary<'a>), Atom> {
    let state = ctx.0.lock().unwrap();
    let echo = protocol::RequestEcho {
        kid: request_kid.as_slice().to_vec(),
        piv: request_piv.as_slice().to_vec(),
        nonce: nonce_from_binary(&request_nonce)?,
    };
    let (code, inner_options, payload) = protocol::unprotect_response(
        &state,
        oscore_option.as_slice(),
        ciphertext.as_slice(),
        class_i_options.as_slice(),
        &echo,
    )
    .map_err(protocol_error_to_atom)?;
    Ok((
        code,
        to_binary(env, &inner_options),
        to_binary(env, &payload),
    ))
}

rustler::init!("Elixir.Oscore.Native");
