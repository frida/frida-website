---
layout: news_item
title: 'Frida 16.7.1 Released'
date: 2025-03-21 13:57:25 +0100
author: oleavr
version: 16.7.1
categories: [release]
---

I am pleased to announce the release of Frida 16.7.1! In this release, we've
been busy improving support across various architectures and fixing some tricky
bugs. A big thank you to [@jpstotz][] and [@philippmao][] for their valuable
contributions!

**Key highlights include:**

- **fruity**: Fixed `Input/Output Error` on Windows by skipping devices with an
  empty UDID. (Thanks to [@jpstotz][])

- **droidy**: Added support for more than ~8 ADB-connected devices by increasing
  the message size limit. (Thanks to [@philippmao][])

- **thumb-relocator**: Improved success rate when hooking tiny functions
  produced by modern toolchains on Android by utilizing LLD alignment padding
  in `can_relocate()`.

- **thumb-relocator**: Restricted padding detection by ensuring the last
  instruction is on a four-byte boundary and is a two-byte instruction.

- **module-registry**: Fixed hooking of tiny ELF notifiers by populating the
  registry before hooking, allowing `CodeAllocator` to locate a nearby
  ELF-header.

- **ci**: Added `arm64be`, `armbe8`, and `armhf-musl` to the Linux CI.

- **env**: Enabled generation of Thumb code on 32-bit ARM for smaller binaries.

- **linux**: Added pthread probing for musl on 32-bit ARM.

- **build**: Fixed `armhf` triplet parsing for musl.

- **devkit**: Also defined `GUM_STATIC` for the Gum devkit so the consumer
  doesn't have to define it.

- **devkit-assets**: Modernized the Gum examples.

- **compiler**: Bumped `@types/frida-gum` to 18.8.1.

As always, happy hacking!

[@jpstotz]: https://github.com/jpstotz
[@philippmao]: https://github.com/philippmao
