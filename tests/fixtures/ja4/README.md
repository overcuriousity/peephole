ClientHellos as sent (the TLS records, nothing else), captured on loopback
in an ubuntu:26.04 container, with the JA4 Wireshark 4.6.4 computed for each
(`tshark -e tls.handshake.ja4`). They pin `trap::tls_hello::ja4` to an
independent implementation.

| file | client | JA4 (Wireshark) |
|---|---|---|
| curl-tls13.bin | `curl -sk --resolve probe.test:…` (OpenSSL 3, SNI, ALPN h2) | `t13d3013h2_1d37bd780c83_8537cf56674e` |
| openssl-tls12.bin | `openssl s_client -connect 127.0.0.1:… -alpn http/1.1 -tls1_2` (no SNI) | `t12i2708h1_a2460661a67a_36cef8aed422` |
