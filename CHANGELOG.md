# Changelog

## v0.1.0

Initial release.

- Security context derivation (RFC 8613 §3.2), AES-CCM-16-64-128 / HKDF-SHA-256.
- Request/response message protection and verification (§5, §6, §8).
- Sequence number and replay window handling (§7.4, Appendix B.1).
- Correctness pinned to RFC 8613 Appendix C test vectors.
