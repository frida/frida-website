---
layout: news_item
title: 'Frida 17.4.0 Released'
date: 2025-10-12 08:35:50 +0200
author: oleavr
version: 17.4.0
categories: [release]
---

Time for another feature-packed release! Highlights:

- simmy: Brand-new backend for talking to Apple’s simulators through
  CoreSimulator.framework. Spawn apps, instrument processes, and generally
  treat simulators like any other device – all from the comfort of Frida.

- darwin: Support early instrumentation of `dyld_sim`, so you can attach and
  load your scripts even at a point before the dynamic loader has finished
  boot-strapping the simulated process.

- darwin: Fix sysroot detection on the latest iOS 18 simulator, where
  `dyld_sim` is now hidden from `_dyld_image_count` and
  `TASK_DYLD_ALL_IMAGE_INFO_64`. Thanks to [@CodeColorist][] for tracking this
  one down!

- fruity: Automatically unpair whenever we encounter an `InvalidHostID`
  error, allowing the next pairing attempt to succeed. Great work by
  [@mrmacete][]!

- android: Update `system-server` to `frida-java-bridge` 7.0.9. Changes:
  - Fix Java.deoptimize\*() and Java.backtrace() on Android 16. Thanks
    [@hsorbo][]!
  - Improve typings. Thanks [@yotamN][]!

- host-session: Add cross-backend communication, so devices discovered through
  one backend are now available to internals in another.

- base: Introduce `StdioPipes` and `FileDescriptor` helpers, shared by the
  Darwin, Linux, and FreeBSD backends.

- value: New `VariantReader.list_members()` helper for easier introspection.

Enjoy!


[@CodeColorist]: https://x.com/CodeColorist
[@mrmacete]: https://x.com/bezjaje
[@hsorbo]: https://x.com/hsorbo
[@yotamN]: https://github.com/yotamN
