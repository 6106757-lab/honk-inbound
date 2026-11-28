Fixed
- Report a missing NFQUEUE subsystem as unavailable for the IPv6 bind as well as the IPv4 bind, so the startup warning names the missing `nfnetlink_queue` module instead of a raw `Invalid argument` error.
