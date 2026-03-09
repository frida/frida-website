---
layout: news_item
title: 'Frida 17.7.0 Released'
date: 2026-02-13 15:12:42 +0100
author: oleavr
version: 17.7.0
categories: [release]
---

This release brings some substantial new Linux capabilities, improved service
plumbing, and a handful of platform-specific fixes across Darwin, Android, and
the API surface.

Highlights include:

- linux: Add a new eBPF-powered `SyscallTracer` service, plus the groundwork
  for future activity sampling.
- droidy: Add support for consuming remote services and implementing services
  locally.
- darwin: Accept `__dyld_apis` dyld section on macOS 26.
- android: Fix spawn package name logic on newer OSes.
- icons: Use `uint16` for icon dimensions, and omit width/height for PNG icons
  on macOS, for consistency with other platforms.
- node: Expand `GVariant` marshaling support, use `BigInt` for 64-bit integers,
  and fix a `Service.request()` lifetime issue that could cause refcount
  underflow and memory corruption.

Thanks to [@veecore][] for the macOS 26 compatibility fix, and to [@hsorbo][]
for co-authoring some of the Linux syscall and BPF map work.


[@veecore]: https://github.com/veecore
[@hsorbo]: https://x.com/hsorbo
