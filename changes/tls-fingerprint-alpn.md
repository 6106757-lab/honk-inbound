Added
- Per-node TLS fingerprint (`fp` share-link parameter): nodes store `tls_fingerprint` (`chrome`, `firefox`, `safari`, `ios`, `android`, `edge`), validated at parse and node validation; REALITY and TLS dials use it.
- TLS fingerprint profiles in the outbound stack: iOS/Safari and Firefox get their own cipher list, curves, signature algorithms and X25519-only key shares (no MLKEM hybrid, no Chrome ALPS/ECH grease); a node with an explicit non-Chromium `fp` leads its first REALITY attempt with X25519 only, so servers that reject the MLKEM hybrid group connect.
- Clash subscriptions now map `client-fingerprint` to the node's TLS fingerprint (the subscription's `fingerprint` key stays the certificate SHA256 pin); a node that only carries its fingerprint in the subscription no longer falls back to Chrome.

Fixed
- XHTTP ALPN check accepts any list containing `h2` (was exactly `["h2"]`), so `alpn=h2,http/1.1` links import; lists without `h2` are still rejected, and duplicate entries are still rejected at admission.
- A probe that times out (deadline) now records an unavailable observation instead of leaving the node latency blank (`-`); cancelled probes and local packet refusals still record nothing.
