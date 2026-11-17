Fixed

- Plain-TLS dials send the WebSocket `Host` name as SNI when no explicit `sni` is set, so CDN-fronted nodes verify the distribution certificate instead of failing on the edge address.
