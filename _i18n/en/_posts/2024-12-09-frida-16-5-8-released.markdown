---
layout: news_item
title: 'Frida 16.5.8 Released'
date: 2024-12-09 00:32:29 +0100
author: oleavr
version: 16.5.8
categories: [release]
---

Exciting new release packed with performance enhancements and bug fixes across
various components, especially in our Fruity backend. [@hsorbo][] and I
collaborated to bring you the following improvements:

- **fruity:** Boost NCM performance with multi-transfers, improving data
  transfer efficiency.
- **fruity:** Improve userspace NCM driver to perform batching, reducing packet
  loss in bursty situations.
- **fruity:** Enable lwIP TCP timestamps and SACK to align with the Linux IP
  stack defaults, enhancing network performance.
- **fruity:** Bump lwIP TCP Maximum Segment Size (MSS) to 4036 for better TCP
  tunnel performance.
- **fruity:** Account for `frida-server` `bind()` delay to improve connection
  establishment reliability.
- **fruity:** Fix crash on USB operation creation during teardown.
- **fruity:** Improve USB device handling on non-macOS systems by avoiding
  unnecessary USB access when kernel NCM is available.
- **fruity:** Fix direct channel reliability by ensuring connections are
  established correctly even when conflicting services are running. Kudos to
  [@mrmacete][] for helping track this one down.
- **fruity:** Improve `TcpTunnelConnection` teardown to ensure proper cleanup
  upon the remote end closing the connection.

- **api:** Generate a proper GObject Introspection Repository (GIR), including
  necessary types and omitting internal ones.
- **api:** Avoid exposing internal types in the API.
- **api:** Omit APIs involving `HostSession`.

- **build:** Modify output logic to avoid redundant writes to output files,
  speeding up incremental builds.
- **build:** Avoid parsing API multiple times by leveraging Meson's
  `custom_target()` support for multiple outputs.
- **compat:** Create relative subproject symlinks so the source tree can be
  moved without breaking builds.
- **compat:** Fix error-handling in `compat.symlink_to()` for subprojects.

- **windows:** Fix `cpu_type_from_pid()` for non-existent PIDs.
- **windows:** Use `GetProcessInformation()` on Windows 11+ to ensure correct
  usage of `ProcessMachineTypeInfo`.

As always, a huge thanks to [@hsorbo][] and [@mrmacete][] for their invaluable
contributions in making this release possible.

[@hsorbo]: https://twitter.com/hsorbo
[@mrmacete]: https://twitter.com/mrmacete
