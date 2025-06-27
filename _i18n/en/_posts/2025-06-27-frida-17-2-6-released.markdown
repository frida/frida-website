---
layout: news_item
title: 'Frida 17.2.6 Released'
date: 2025-06-27 16:00:01 +0200
author: oleavr
version: 17.2.6
categories: [release]
---

We're excited to announce Frida 17.2.6, featuring two important fixes:

- **buffer**: Fix `max_length` in `read_fixed_string()`.

  The `max_length` is now properly constrained within both the requested size
  and the buffer's size.

  Thanks [@mrmacete][]!

- **agent**: Disable Exceptor for the emulated realm.

  Exceptor needs to hook `signal()` and `sigaction()`, but they are in libc.
  This leads to `gum_mprotect()` aborting because it cannot change libc's
  read-only mapping. This fix prevents the crash observed when using
  `frida-server` or `frida-inject` on Android 14 and 15 AVDs.

  Thanks [@ptrstr][]!


[@mrmacete]: https://twitter.com/bezjaje
[@ptrstr]: https://github.com/ptrstr
