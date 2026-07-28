# OSCORE

An Elixir implementation of [RFC 8613](https://www.rfc-editor.org/rfc/rfc8613) (Object Security for Constrained RESTful Environments), with the protocol core implemented in Rust and exposed through a [Rustler](https://github.com/rusterlium/rustler) NIF.

OSCORE provides end-to-end encryption and integrity protection for CoAP messages, independent of the transport.
This library implements the security-context derivation, message protection/verification, and replay-window logic defined by RFC 8613.
CoAP message framing and OSCORE option classification (Class E/I/U) are left to the caller - this library only handles the encrypt/decrypt boundary.

## Why Rust

The security-critical parts (HKDF context derivation, AEAD nonce/AAD construction, AES-CCM encryption) are implemented in Rust on top of the [RustCrypto](https://github.com/RustCrypto) primitives (`aes`, `ccm`, `hkdf`, `sha2`) rather than reimplemented from scratch in Elixir.
Correctness is pinned to the exact test vectors published in RFC 8613 Appendix C.

## Status

v0.1.0 implements:

- Security context derivation (RFC 8613 §3.2), with the mandatory AES-CCM-16-64-128 / HKDF-SHA-256 suite, including an optional ID Context.
- Request/response message protection and verification (§5, §6, §8), including the "reuse the request's nonce" response mode.
- The `kid context` (§6.1) is carried in the OSCORE option of protected requests and verified on the receiving side when an ID Context is in use.
- Sender Sequence Numbers and the §7.4 sliding replay window.
- A hook for Appendix B.1 sequence-number persistence: `OSCORE.sender_seq/1` reads the counter and `derive_context`'s `:sender_seq` option restores it, so the same AEAD nonce is never reused across restarts.

Not yet implemented (open follow-ups):

- EDHOC or any other key-exchange mechanism - callers supply the Master Secret/Salt directly.
- Group OSCORE and Appendix B.2 (Echo-based context resynchronization after reboot).
- Replay protection for responses carrying their own Partial IV (needed for Observe notifications beyond the first).
- AEAD suites other than AES-CCM-16-64-128.

## Installation

Add `oscore` as a dependency in `mix.exs`:

```elixir
def deps do
  [
    {:oscore, "~> 0.1.0"}
  ]
end
```

A Rust toolchain (`cargo`, `rustc`) must be available at build time - the NIF is compiled from source, not fetched as a precompiled binary.

## Usage

```elixir
{:ok, ctx} =
  OSCORE.derive_context(
    master_secret: master_secret,
    master_salt: master_salt,
    sender_id: <<0x00>>,
    recipient_id: <<0x01>>
  )

{:ok, protected, echo} =
  OSCORE.protect_request(ctx, code: 0x01, inner_options: inner_options, payload: payload)

# ... send protected.oscore_option / protected.ciphertext, receive a response ...

{:ok, code, inner_options, payload} =
  OSCORE.unprotect_response(ctx, echo,
    oscore_option: response_oscore_option,
    ciphertext: response_ciphertext
  )
```

## License

MIT, see [LICENSE.md](LICENSE.md).

## Getting involved

🗨️ **Contact us:**
Feel free to contact me on [Linkedin](https://www.linkedin.com/in/thiago-cesar-calori-esteves-972368115/).

## ☕ Support the project

Jellyfish is free and open source. If it's useful to you, consider supporting its development:

 * **GitHub Sponsors:** [github.com/sponsors/thiagoesteves](https://github.com/sponsors/thiagoesteves)
 * **BTC Wallet Address:** `bc1q3f5eyg2qlun6dc4l597yuyygmkh2qvklwecw8r`
 * **ETH Wallet Address:** `0x151C3A7AE305b3fF385c7EEce72C6c4E23dE05Fa`
