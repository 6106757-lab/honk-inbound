Fixed
- The splice relay now shares the copy relay's monotonic idle-drain deadline, so delayed polling no longer extends an idle drain; the DNS retry test that pinned successful retries not penalizing a Score candidate is restored.
