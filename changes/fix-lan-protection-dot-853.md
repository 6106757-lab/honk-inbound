Fixed

- LAN self-protection checks stop misreporting rules that exclude or match DNS-over-TLS port 853: 853 now counts as a DNS port alongside 53, so a `!dport(53, 853)` direct rule confirms and a `dport(853)` block rule is correctly skipped instead of failing the check.
