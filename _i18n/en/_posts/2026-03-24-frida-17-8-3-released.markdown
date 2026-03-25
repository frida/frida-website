---
layout: news_item
title: 'Frida 17.8.3 Released'
date: 2026-03-24 15:41:16 +0100
author: oleavr
version: 17.8.3
categories: [release]
---

This release brings another round of fixes and documentation improvements:

### Fixes

- **fruity**: Fix `TcpTunnelConnection` stalls caused by deferred CDTunnel TLS
  records larger than 8192 bytes. Send a minimal dummy IPv6 datagram when
  needed to trigger delivery of deferred data and improve reliability.
  Kudos to [@hsorbo][] for reporting and helping track this down, and
  [@tux-mind][] for identifying the root cause.

- **fruity**: Fix jailed `spawn()` on iOS 26.4 betas.
  Thanks [@mrmacete][]!

- **fruity**: Fix `TreeSet` comparator behavior where transports with the same
  score may be treated as equal and dropped, causing Frida to prefer `usbmuxd`
  with lwIP over an already available CoreDevice tunnel on macOS.
  Kudos to [@tux-mind][] for reporting and helping track this down.

- **fruity**: Handle early tunnel loss, e.g. when `remotepairingdeviced`
  crashes.

- **android**: Adjust the RTLD path if `dlopen(libart)` fails.
  Thanks [@sam0holix][]!

### Documentation

- **docs**: Revise macOS certificate identifiers in the README to better
  support setups with multiple Apple Development certificates and avoid
  ambiguous certificate selection during `make`.
  Thanks [@samykamkar][]!

- **docs**: Update the README to include the `websockets` package in the
  installation instructions required by `frida-trace`.
  Thanks [@samykamkar][]!


[@hsorbo]: https://x.com/hsorbo
[@tux-mind]: https://github.com/tux-mind
[@mrmacete]: https://x.com/bezjaje
[@sam0holix]: https://github.com/sam0holix
[@samykamkar]: https://github.com/samykamkar
