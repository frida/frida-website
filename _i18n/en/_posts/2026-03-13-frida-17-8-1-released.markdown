---
layout: news_item
title: 'Frida 17.8.1 Released'
date: 2026-03-13 13:22:16 +0100
author: oleavr
version: 17.8.1
categories: [release]
---

This release brings a bunch of fixes and compatibility improvements across
Android, Linux, musl-based systems, and newer LLVM toolchains:

- android: Only load in namespace if the ART namespace actually exists.
- android: Handle Chrome's zygote process so it stays invisible to spawn
  gating, while its children continue to be gated as expected.
- android: Bump to Android NDK r29 and target API 21 on all architectures, as
  older API levels are no longer supported by the latest NDK.
- linux: Improve process enumeration so `uid` is always present, user lookup is
  more robust, and indeterminate or undersized getpwuid_r() buffers are handled
  correctly.
- linux: Avoid an rtld notifier deadlock on musl.
- linux: Handle missing /proc in the debugger check.
- compiler: Add a musl-compatible backend mode that runs the Go compiler
  backend out-of-process as a persistent helper, avoiding TLS-related
  limitations when frida-core is loaded after startup or through dlopen().
- libc-shim: Plug more stdio API holes, including setbuf(), setlinebuf(),
  setbuffer(), __srget(), and fix the setbuffer() signature on glibc + musl.
- meson: Fix linking on modern LLVM/LLD toolchains by using FreeBSD-specific
  version scripts where needed.

Enjoy!
