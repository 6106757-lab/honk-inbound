Fixed
- The UDP detour pre-screen now skips Shadowsocks and SOCKS5 fronts that name their own detour, so a group falls through to the next member instead of failing the whole dial at the front's leaf refusal. A front naming `direct` is still eligible, like the leaf guards.
