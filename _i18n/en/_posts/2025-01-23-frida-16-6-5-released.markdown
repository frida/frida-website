---
layout: news_item
title: 'Frida 16.6.5 Released'
date: 2025-01-23 20:47:10 +0100
author: oleavr
version: 16.6.5
categories: [release]
---

This release brings a set of improvements and fixes in our Linux and Android
support, with contributions from [@kaftejiman][] and [@DoranekoSystems][]. We've
also improved how we talk to Apple devices across the network.

Here's what's new:

- **linux**: Improve injector to avoid risky code swaps with memfd regions
  (thanks to [@kaftejiman][]). Memfd regions may not be writable, and unlike
  regular regions, `ptrace()` won't help us in case of a missing writable bit.

- **linux**: Relax injector's libc matching for Android (thanks to
  [@kaftejiman][]). This means we can still match them with bind-mounted APEXes.

- **linux**: Optimize `NativePointer#readVolatile()` (JS) / `gum_memory_read()`
  (C) for Linux/Android (thanks to [@DoranekoSystems][]). By making use of
  `process_vm_readv()` if the kernel supports it, we can avoid parsing memory
  maps. This means instead of being well above 1000x slower compared to direct
  access, it is now only about 1.45x slower.

- **fruity**: Support networked lockdown for `CoreDevice`. We need to provide
  the remote unlock host key as part of the `RSDCheckin`. Kudos to [@as0ler][]
  and [@mrmacete][] for reporting and helping get to the bottom of this one.

[@kaftejiman]: https://github.com/kaftejiman
[@DoranekoSystems]: https://github.com/DoranekoSystems
[@as0ler]: https://github.com/as0ler
[@mrmacete]: https://github.com/mrmacete
