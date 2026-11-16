Fixed

- DNS cache now stores only successful resolutions that yield an address. NXDOMAIN, SERVFAIL, NODATA, CNAME-only answers, rejected answers, and REFUSED synthetics are never cached and never evict an existing positive, so an expired positive keeps serving stale and the next query re-asks upstream.
- Removed the negative cache entirely, including its OpenAPI `negative` coverage and `entry_kinds` entries. Persisted rows without an address are skipped on restore.
