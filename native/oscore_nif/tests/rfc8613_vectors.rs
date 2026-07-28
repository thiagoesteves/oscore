//! RFC 8613 Appendix C test vectors, exercised through the crate's public
//! (non-NIF) modules by including the crate source directly, since the crate
//! itself compiles to a cdylib and cannot be linked as a regular rlib dep.

#[path = "../src/aead.rs"]
mod aead;
#[path = "../src/context.rs"]
mod context;
#[path = "../src/option.rs"]
mod option;
#[path = "../src/protocol.rs"]
mod protocol;
#[path = "../src/replay.rs"]
mod replay;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

struct KeyDerivationVector {
    master_secret: &'static str,
    master_salt: &'static str,
    id_context: Option<&'static str>,
    sender_id: &'static str,
    recipient_id: &'static str,
    sender_key: &'static str,
    recipient_key: &'static str,
    common_iv: &'static str,
}

fn check_key_derivation(v: &KeyDerivationVector) {
    let derived = context::derive(
        &hex(v.master_secret),
        &hex(v.master_salt),
        &hex(v.sender_id),
        &hex(v.recipient_id),
        v.id_context.map(hex).as_deref(),
    );
    assert_eq!(derived.sender_key.to_vec(), hex(v.sender_key), "sender key");
    assert_eq!(
        derived.recipient_key.to_vec(),
        hex(v.recipient_key),
        "recipient key"
    );
    assert_eq!(derived.common_iv.to_vec(), hex(v.common_iv), "common iv");
}

/// RFC 8613 Appendix C.1: Key Derivation with Master Salt.
#[test]
fn c1_key_derivation_with_master_salt() {
    check_key_derivation(&KeyDerivationVector {
        master_secret: "0102030405060708090a0b0c0d0e0f10",
        master_salt: "9e7ca92223786340",
        id_context: None,
        sender_id: "",
        recipient_id: "01",
        sender_key: "f0910ed7295e6ad4b54fc793154302ff",
        recipient_key: "ffb14e093c94c9cac9471648b4f98710",
        common_iv: "4622d4dd6d944168eefb54987c",
    });

    // Server side: Sender/Recipient swapped.
    check_key_derivation(&KeyDerivationVector {
        master_secret: "0102030405060708090a0b0c0d0e0f10",
        master_salt: "9e7ca92223786340",
        id_context: None,
        sender_id: "01",
        recipient_id: "",
        sender_key: "ffb14e093c94c9cac9471648b4f98710",
        recipient_key: "f0910ed7295e6ad4b54fc793154302ff",
        common_iv: "4622d4dd6d944168eefb54987c",
    });
}

/// RFC 8613 Appendix C.2: Key Derivation without Master Salt.
#[test]
fn c2_key_derivation_without_master_salt() {
    check_key_derivation(&KeyDerivationVector {
        master_secret: "0102030405060708090a0b0c0d0e0f10",
        master_salt: "",
        id_context: None,
        sender_id: "00",
        recipient_id: "01",
        sender_key: "321b26943253c7ffb6003b0b64d74041",
        recipient_key: "e57b5635815177cd679ab4bcec9d7dda",
        common_iv: "be35ae297d2dace910c52e99f9",
    });
}

/// RFC 8613 Appendix C.3: Key Derivation with ID Context.
#[test]
fn c3_key_derivation_with_id_context() {
    check_key_derivation(&KeyDerivationVector {
        master_secret: "0102030405060708090a0b0c0d0e0f10",
        master_salt: "9e7ca92223786340",
        id_context: Some("37cbf3210017a2d3"),
        sender_id: "",
        recipient_id: "01",
        sender_key: "af2a1300a5e95788b356336eeecd2b92",
        recipient_key: "e39a0c7c77b43f03b4b39ab9a268699f",
        common_iv: "2ca58fb85ff1b81c0b7181b85e",
    });
}

fn client_context(v: &KeyDerivationVector) -> context::ContextState {
    context::ContextState::new(
        &hex(v.master_secret),
        &hex(v.master_salt),
        hex(v.sender_id),
        hex(v.recipient_id),
        v.id_context.map(hex).as_deref(),
    )
}

/// RFC 8613 Appendix C.4: OSCORE Request, Client (context from C.1).
#[test]
fn c4_oscore_request() {
    let v = KeyDerivationVector {
        master_secret: "0102030405060708090a0b0c0d0e0f10",
        master_salt: "9e7ca92223786340",
        id_context: None,
        sender_id: "",
        recipient_id: "01",
        sender_key: "f0910ed7295e6ad4b54fc793154302ff",
        recipient_key: "ffb14e093c94c9cac9471648b4f98710",
        common_iv: "4622d4dd6d944168eefb54987c",
    };
    let mut ctx = client_context(&v);
    ctx.sender_seq = 20;

    let (protected, echo) =
        protocol::protect_request(&mut ctx, 0x01, &hex("b3747631"), &[]).unwrap();

    assert_eq!(protected.oscore_option, hex("0914"));
    assert_eq!(protected.ciphertext, hex("612f1092f1776f1c1668b3825e"));
    assert_eq!(echo.piv, hex("14"));
    assert_eq!(ctx.sender_seq, 21);
}

/// RFC 8613 Appendix C.5: OSCORE Request, Client (context from C.2).
#[test]
fn c5_oscore_request_no_salt() {
    let v = KeyDerivationVector {
        master_secret: "0102030405060708090a0b0c0d0e0f10",
        master_salt: "",
        id_context: None,
        sender_id: "00",
        recipient_id: "01",
        sender_key: "321b26943253c7ffb6003b0b64d74041",
        recipient_key: "e57b5635815177cd679ab4bcec9d7dda",
        common_iv: "be35ae297d2dace910c52e99f9",
    };
    let mut ctx = client_context(&v);
    ctx.sender_seq = 20;

    let (protected, _echo) =
        protocol::protect_request(&mut ctx, 0x01, &hex("b3747631"), &[]).unwrap();

    assert_eq!(protected.oscore_option, hex("091400"));
    assert_eq!(protected.ciphertext, hex("4ed339a5a379b0b8bc731fffb0"));
}

/// RFC 8613 Appendix C.6: OSCORE Request, Client, with 'kid context' (context from C.3).
#[test]
fn c6_oscore_request_with_id_context() {
    let v = KeyDerivationVector {
        master_secret: "0102030405060708090a0b0c0d0e0f10",
        master_salt: "9e7ca92223786340",
        id_context: Some("37cbf3210017a2d3"),
        sender_id: "",
        recipient_id: "01",
        sender_key: "af2a1300a5e95788b356336eeecd2b92",
        recipient_key: "e39a0c7c77b43f03b4b39ab9a268699f",
        common_iv: "2ca58fb85ff1b81c0b7181b85e",
    };
    let mut ctx = client_context(&v);
    ctx.sender_seq = 20;

    let (protected, _echo) =
        protocol::protect_request(&mut ctx, 0x01, &hex("b3747631"), &[]).unwrap();

    // protect_request must emit the kid context (the 'h' flag) directly when the
    // context was derived with an ID Context.
    assert_eq!(protected.oscore_option, hex("19140837cbf3210017a2d3"));
    assert_eq!(protected.ciphertext, hex("72cd7273fd331ac45cffbe55c3"));
}

/// RFC 8613 Appendix C.7: OSCORE Response, Server, reusing the request's nonce
/// (context: server side of C.1, i.e. Sender ID 0x01 / Recipient ID empty).
#[test]
fn c7_oscore_response_reusing_request_nonce() {
    let v = KeyDerivationVector {
        master_secret: "0102030405060708090a0b0c0d0e0f10",
        master_salt: "9e7ca92223786340",
        id_context: None,
        sender_id: "01",
        recipient_id: "",
        sender_key: "ffb14e093c94c9cac9471648b4f98710",
        recipient_key: "f0910ed7295e6ad4b54fc793154302ff",
        common_iv: "4622d4dd6d944168eefb54987c",
    };
    let mut ctx = client_context(&v);

    // The request from C.4: kid = "" (client's Sender ID), piv = 0x14.
    let request_echo = protocol::RequestEcho {
        kid: hex(""),
        piv: hex("14"),
        nonce: aead::compute_nonce(&hex(""), &hex("14"), &ctx.common_iv.clone()),
    };
    assert_eq!(
        request_echo.nonce.to_vec(),
        hex("4622d4dd6d944168eefb549868")
    );

    let protected =
        protocol::protect_response(&mut ctx, 0x45, &[], b"Hello World!", &request_echo, true)
            .unwrap();

    assert_eq!(protected.oscore_option, Vec::<u8>::new());
    assert_eq!(
        protected.ciphertext,
        hex("dbaad1e9a7e7b2a813d3c31524378303cdafae119106")
    );
    // Reusing the request's nonce must not advance the Sender Sequence Number.
    assert_eq!(ctx.sender_seq, 0);
}

/// Full request+response round trip between independently derived client and
/// server contexts (the security contexts from Appendix C.1), verifying that
/// protect on one side and unprotect on the other agree end to end.
#[test]
fn round_trip_request_and_response() {
    let master_secret = hex("0102030405060708090a0b0c0d0e0f10");
    let master_salt = hex("9e7ca92223786340");

    let mut client =
        context::ContextState::new(&master_secret, &master_salt, hex(""), hex("01"), None);
    let mut server =
        context::ContextState::new(&master_secret, &master_salt, hex("01"), hex(""), None);

    let (protected_req, client_echo) =
        protocol::protect_request(&mut client, 0x01, &hex("b3747631"), &[]).unwrap();

    let (server_code, server_inner_options, server_payload, server_echo) =
        protocol::unprotect_request(
            &mut server,
            &protected_req.oscore_option,
            &protected_req.ciphertext,
            &[],
        )
        .unwrap();

    assert_eq!(server_code, 0x01);
    assert_eq!(server_inner_options, hex("b3747631"));
    assert_eq!(server_payload, Vec::<u8>::new());
    assert_eq!(server_echo.nonce, client_echo.nonce);

    let protected_resp =
        protocol::protect_response(&mut server, 0x45, &[], b"Hello World!", &server_echo, true)
            .unwrap();

    let (client_code, client_inner_options, client_payload) = protocol::unprotect_response(
        &client,
        &protected_resp.oscore_option,
        &protected_resp.ciphertext,
        &[],
        &client_echo,
    )
    .unwrap();

    assert_eq!(client_code, 0x45);
    assert_eq!(client_inner_options, Vec::<u8>::new());
    assert_eq!(client_payload, b"Hello World!".to_vec());
}

/// A second request must be rejected by the server's replay window once its
/// Partial IV has already been seen.
#[test]
fn rejects_replayed_request() {
    let master_secret = hex("0102030405060708090a0b0c0d0e0f10");
    let master_salt = hex("9e7ca92223786340");

    let mut client =
        context::ContextState::new(&master_secret, &master_salt, hex(""), hex("01"), None);
    let mut server =
        context::ContextState::new(&master_secret, &master_salt, hex("01"), hex(""), None);

    let (protected_req, _echo) =
        protocol::protect_request(&mut client, 0x01, &hex("b3747631"), &[]).unwrap();

    protocol::unprotect_request(
        &mut server,
        &protected_req.oscore_option,
        &protected_req.ciphertext,
        &[],
    )
    .unwrap();

    let replay = protocol::unprotect_request(
        &mut server,
        &protected_req.oscore_option,
        &protected_req.ciphertext,
        &[],
    );
    assert!(matches!(replay, Err(protocol::ProtocolError::Replayed)));
}
