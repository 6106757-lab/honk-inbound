Internal

- Fix the clippy findings the 1.99 toolchain reports with `-D warnings`: `is_multiple_of` for the rate-limited log counters, collapsed `if let` chains, `is_none_or` for the inbound-not match, a removed dead `FetchFailure` re-export, a single-element benchmark loop, and `&[b'x'; 64]` instead of `&vec![b'x'; 64]`.
