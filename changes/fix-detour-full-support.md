Fixed

- DNS cache now stores only successful resolutions that yield an address. NXDOMAIN, SERVFAIL, NODATA, CNAME-only answers, rejected answers, and REFUSED synthetics are never cached and never evict an existing positive, so an expired positive keeps serving stale and the next query re-asks upstream.
- Removed the negative cache entirely, including its OpenAPI `negative` coverage and `entry_kinds` entries. Persisted rows without an address are skipped on restore.
- Detour dials now race every resolved address of the target server instead of dialling only the first one, matching direct dials. A dead first address no longer fails the dial, and a REALITY re-dial reuses the address the race already won instead of resolving again.
