# Scanners we do not counter-scan

Peephole answers reconnaissance with a counter-scan of the source — except
when the source is verified to be someone who scans the open internet as a
service, not an attacker. Counter-scanning them would hit the operator of a
documented service and buy nothing.

Verification is forward-confirmed reverse DNS (FCrDNS), the same mechanism
Google recommends for Googlebot: the address's PTR record must name a host
under the operator's domain, and that host must resolve back to the
address. A user-agent header alone proves nothing — anyone can send
`CensysInspect/1.1` or `zgrab` — so it is never accepted.

## Exempt operators

| Operator | Reverse zone | Reference |
|---|---|---|
| Censys | `*.censys-scanner.com` | <https://support.censys.io> (scanner IPs and UA) |
| LeakIX | `*.scan.leakix.org` | <https://leakix.net> (l9scan/l9explore) |
| Shodan | `*.shodan.io` | <https://www.shodan.io> (census hosts) |

Search engines and link-preview fetchers (Google, Bing, Apple, Yandex,
Baidu, Petal, Amazon) are exempt through the same check; their zones are
listed next to these in `src/scan/crawler.rs` (`DOMAINS`).

An operator whose reverse zone lapses becomes scannable again automatically
— verification runs per scan job, not once.

## Are you a scanner operator?

Publish your scanner addresses under a dedicated reverse zone that
forward-confirms, send a PR adding the zone to `DOMAINS` in
`src/scan/crawler.rs` and a row here, and peephole will leave your
addresses alone. Ranges without FCrDNS (a plain IP list) are not accepted:
a list file cannot prove who holds an address tomorrow.

## Seeing who was refused

Admin → Scans lists every refused scan job with its reason
(`status=refused`), e.g. `verified crawler (177.186.132.66.censys-scanner.com)`;
the pace card links the last 24 hours' refusals.
