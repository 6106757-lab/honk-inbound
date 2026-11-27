Fixed
- Validate `subtag()` regexes at config validation (`subtag-dns-regex`) instead of failing at router construction, and stop splitting a `regex:` argument on a comma inside a `{n,m}` quantifier, `(...)` group or `[...]` character class, so unquoted comma regexes work in DNS `subtag()`/`qname()`, group filters and traffic-routing `domain()`.
