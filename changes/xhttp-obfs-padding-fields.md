Fixed

- XHTTP nodes carrying Xray obfs padding claims (`xPaddingObfsMode`, `xPaddingMethod`, `xPaddingPlacement`, `xPaddingHeader`, `xPaddingKey`) import instead of being rejected as malformed, so edgetunnel XHTTP links work; the claims are stored but do not yet shape requests.
