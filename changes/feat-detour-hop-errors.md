Changed
- Detour dial failures now name the failing hop: `detour hop 0 (socks-a): …` counts legs outward from the rider, so a dead front is visible in the error instead of hiding behind the rider's name. Failures are also attributed to that front in liveness tracking, not to the rider.
- Every leg of a detour dial shares one deadline: each leg waits at most `min(connect_timeout, time left on the dial)`, so a silent second hop fails on the shared deadline instead of burning its own full timeout.
- A detour that points back at itself (or cycles through other nodes) now fails fast at 4 hops with `detour depth exceeds 4` instead of descending until the dial timeout.
