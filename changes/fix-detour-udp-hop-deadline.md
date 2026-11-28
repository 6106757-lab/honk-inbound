Fixed
- UDP detour legs now share the dial's deadline and hop count with the TCP
  legs: a nested UDP leg waits at most the time left on the dial and reports
  its own hop, instead of restarting the hop count and the deadline.
- A detour cycle over UDP now fails fast at 4 legs with `detour depth exceeds
  4`, the same cap the TCP legs already had.
