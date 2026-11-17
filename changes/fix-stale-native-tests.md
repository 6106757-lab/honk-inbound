Internal

- Fix the stale native flow and netlink tests: the TCP close test now expects the row reclaimed at retirement admission, the UDP removal test asserts the tombstone is already reclaimed after a failed cleanup, and the netkit fallback test accepts EINVAL and ENOSYS as missing-driver signals.
