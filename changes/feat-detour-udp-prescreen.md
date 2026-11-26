Fixed
- Group detours now screen UDP front carriers before dialing: a front that cannot hand the rider a working UDP transport (or rejects the target port) is skipped for the next member, and the dial fails fast with "detour could not carry UDP to …" instead of burning the dial timeout; protocols that cannot ride a group detour on UDP fail before dialing instead of inside it.
