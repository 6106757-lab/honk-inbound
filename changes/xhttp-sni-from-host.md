Fixed

- Plain-TLS dials send the XHTTP `host` name as SNI when no explicit `sni` is set, so CDN-fronted XHTTP nodes verify the distribution certificate instead of failing on the edge address.
