Fixed

- XHTTP nodes with obfs padding configured now send the padding (queryInHeader, header, query or cookie placement) instead of the standard Referer padding, so edgetunnel-style endpoints that route on the padding header can be reached.
