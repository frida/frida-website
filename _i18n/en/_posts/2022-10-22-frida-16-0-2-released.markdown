---
layout: news_item
title: 'Frida 16.0.2 Released'
date: 2022-10-22 01:59:41 +0200
author: oleavr
version: 16.0.2
categories: [release]
---

It's Friday! Here's a brand new release with lots of improvements:

- macOS: Fix support for attaching to arm64e system apps and services on
  macOS >= 12.
- i/macOS: Upgrade support for chained fixups.
- iOS: Fix system session on arm64e devices running iOS < 14.
- system-session: Disable Exceptor and monitors.
  - Exceptor interferes with the signal handling of the hosting process, which
    is risky and prone to conflict.
  - Monitors aren't really useful for the system session.
- interceptor: Fix trampolines used in grafted mode on iOS/arm64. Thanks [@mrmacete][]!
- compiler: Fix stability issues on multiple platforms.
- compiler: Fix the @frida/path shim.
- compiler: Speed things up by also making use of snapshot on non-x86/64 Linux.
- devkit: Fix regressions in the Windows, macOS, and Linux devkits.
- v8: Fix heap corruptions caused by our libc-shim failing to implement
  malloc_usable_size() APIs, which V8 relies on.
- v8: Fix support for scripts using different snapshots, which was broken due to
  V8 previously being configured to share read-only space across isolates. That
  option conflicts with multiple snapshots.
- v8: Improve teardown.
- v8: Fix v8::External API contract violations.
- v8: Upgrade to 10.9.42.
- zlib: Upgrade to 1.2.13.
- gum: Fix subproject build for ELF-based OSes.
- python: Fix tags of published Linux wheels.
  - Add legacy platform tags so older versions of pip recognize them.
  - Pretend some of the wheels require glibc >= 2.17, as lower versions
    aren't recognized on certain architectures.


[@mrmacete]: https://twitter.com/bezjaje
