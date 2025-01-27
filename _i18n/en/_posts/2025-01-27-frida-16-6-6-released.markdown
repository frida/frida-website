---
layout: news_item
title: 'Frida 16.6.6 Released'
date: 2025-01-27 20:54:40 +0100
author: oleavr
version: 16.6.6
categories: [release]
---

This release brings important bug fixes and optimizes volatile memory writes on
Linux and Android. Big thanks to [@DoranekoSystems][] for his contribution.

- **fruity**: Fix regression in lockdown over CoreDevice introduced in the
  previous release, where `RSDCheckin` now includes an `EscrowBag` to support
  networked lockdown with services such as `com.apple.crashreportmover`. This
  turned out to break support for certain services lacking the privilege to talk
  to `AppleKeyStoreUserClient`. We now maintain a list of such services to omit
  the `EscrowBag` for them. Thanks to [@as0ler][] for reporting and helping
  troubleshoot.

- **darwin**: Fix sysroot detection on Apple Silicon so we can resolve modules
  correctly inside Simulator processes. Kudos to [@stacksmashing][] for
  reporting.

- **linux**: Optimize `NativePointer#writeVolatile()` (JS) /
  `gum_memory_write()` (C) for Linux/Android (thanks to [@DoranekoSystems][]).
  By making use of `process_vm_writev()` if the kernel supports it, we can avoid
  parsing memory maps. This means it is now thousands of times faster.

[@DoranekoSystems]: https://github.com/DoranekoSystems
[@as0ler]: https://github.com/as0ler
[@stacksmashing]: https://x.com/ghidraninja
