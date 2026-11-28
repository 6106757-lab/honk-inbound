Fixed
- Shadowsocks and SOCKS5 nodes that name a `dialer-proxy` no longer dial UDP directly: their UDP dial is refused before any packet is sent, instead of silently bypassing the front. TCP already rode the front (or refused); UDP now fails closed the same way.
