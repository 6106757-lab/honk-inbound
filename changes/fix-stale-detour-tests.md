Internal

- The detour/QUIC tests follow the refactors they lagged behind: the QUIC client test reads the renamed `dial_endpoint`, the Hysteria2 test covers port-hopping refusal now that obfuscation rides a detour, and the packet-transport test expects wrong-source datagrams to be dropped; the tree is formatted with `cargo fmt`.
