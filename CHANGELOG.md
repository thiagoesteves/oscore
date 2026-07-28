# Changelog (v0.2.X)

## 0.2.0

### ⚠️ Backwards incompatible changes for 0.1.0
 * [[`PR-2`](https://github.com/thiagoesteves/oscore/pull/2)] `derive_context/1` now returns `{:error, :id_too_long}` when a Sender or Recipient ID exceeds 7 bytes, where the NIF previously panicked. Callers that pattern-match only on `{:ok, _}` for an over-long ID now hit a clean error.
 * [[`PR-2`](https://github.com/thiagoesteves/oscore/pull/2)] When a context sets `:id_context`, `protect_request` now emits the `h` flag plus the kid context on the wire (RFC 8613 §6.1), and `unprotect_request` rejects a mismatch with `:unknown_id_context`. Default output (no `:id_context`) is unchanged and still matches the RFC C.4/C.5/C.7 vectors bit for bit.

### Bug fixes
 * [[`PR-2`](https://github.com/thiagoesteves/oscore/pull/2)] ID length is now validated at `derive_context`: IDs longer than the nonce allows (7 bytes) return `{:error, :id_too_long}` instead of reaching a Rust `assert!` and panicking inside the NIF.
 * [[`PR-2`](https://github.com/thiagoesteves/oscore/pull/2)] `id_context` is now wired through end to end. It was derived into the keys but discarded, so `protect_request` could never emit the kid context and `unprotect_request` never checked it.

### Enhancements
 * [[`PR-2`](https://github.com/thiagoesteves/oscore/pull/2)] Sequence-number persistence hook (RFC 8613 Appendix B.1): `OSCORE.sender_seq/1` reads the Sender Sequence Number counter and `derive_context`'s `:sender_seq` option restores it, so the counter can survive a restart and the same AEAD nonce is never reused under the same key.
 * [[`PR-2`](https://github.com/thiagoesteves/oscore/pull/2)] Added a `debug_assert` documenting the `<= 8`-byte invariant in `be_bytes_to_u64`.

# 🚀 Previous Releases
 * [v0.1.0 (2026-07-27)](https://github.com/thiagoesteves/oscore/blob/v0.1.0/CHANGELOG.md)
