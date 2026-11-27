Fixed
- A REALITY node with an explicit `fp` no longer switches key shares on a
mask-certificate retry: the first attempt already sends the pinned
fingerprint's hello, so a retry that swaps the hybrid share would send a
hello the user never asked for. The mask-certificate error is returned
instead. Nodes without `fp` keep the hybrid-first retry that falls back to
classical X25519-only shares.
- The mask-certificate check now walks the error cause chain instead of only
matching the outermost error type, so a wrapped mask-certificate error
still triggers the retry where one applies.
