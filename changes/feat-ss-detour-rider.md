Fixed
- Shadowsocks can now ride a detour: its TCP handshake runs over the already-connected front stream instead of requiring a real socket, so a Shadowsocks node works as a group-detour member and through its own dialer-proxy. UDP through a group detour is still refused before dialing.
