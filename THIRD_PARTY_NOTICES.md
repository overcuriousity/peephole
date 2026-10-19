# Third-party notices

peephole is licensed under Apache-2.0 or MIT (see [README](README.md#license)).
It also ships the data below, under its own licence. Rust crate
dependencies are listed in `Cargo.lock` with their licences checked by
`cargo deny` (`deny.toml`).

## X4BNet lists_vpn: datacenter ASN list

- File: [`rules/evidence/x4bnet/ASN.txt`](rules/evidence/x4bnet/ASN.txt),
  built into the binary unmodified; nodes refresh it from
  <https://raw.githubusercontent.com/X4BNet/lists_vpn/main/input/datacenter/ASN.txt>.
- Source: <https://github.com/X4BNet/lists_vpn>, snapshot of commit
  `5eaa1bb207164e270eeee579b3d0a09edd794fa1` (2026-10-17).
- Use: the `net.hosting` evidence rows ([docs/detection.md](docs/detection.md#as-type)).
- Licence: MIT, which per the upstream README covers the list itself. Text
  as published there (also in [`rules/evidence/x4bnet/LICENSE`](rules/evidence/x4bnet/LICENSE)):

```
MIT License

Copyright (c) 2024 X4B (Mathew Heard)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
