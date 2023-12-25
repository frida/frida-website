---
layout: news_item
title: 'Frida 16.1.9 Released'
date: 2023-12-20 00:40:51 +0100
author: oleavr
version: 16.1.9
categories: [release]
---

Quite a few goodies in this release:

- interceptor: Pause cloaked threads too. This prevents random SIGBUS crashes on
  our own threads while using Interceptor to hook functions residing on the same
  page as any of the ones potentially used internally. Thanks [@mrmacete][]!
- darwin: Move to our POSIX Exceptor backend. Mach exception handling APIs have
  become increasingly restrictive in recent Apple OS versions.
- darwin: Resolve import trampolines on arm64, allowing us to hook targets such
  as sigaction().
- linux: Improve spawn() to handle r_brk being hit again.
- linker: Improve spawn() to consider on-disk ELF for RTLD symbols. This means
  we might find r_debug on additional Android systems, for example.
- linux: Fix spawn() when DT_INIT_ARRAY contains sentinel values.
- linux: Improve spawn() to use DT_PREINIT_ARRAY if present.
- android: Handle symlinks in RTLD fallback logic.


[@mrmacete]: https://x.com/bezjaje
