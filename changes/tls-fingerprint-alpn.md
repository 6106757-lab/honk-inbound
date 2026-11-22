Added
- Per-node TLS fingerprint (`fp` share-link parameter): nodes store `tls_fingerprint` (`chrome`, `firefox`, `safari`, `ios`, `android`, `edge`), validated at parse and node validation; REALITY and TLS dials use it.

Fixed
- XHTTP ALPN check accepts any list containing `h2` (was exactly `["h2"]`), so `alpn=h2,http/1.1` links import.
