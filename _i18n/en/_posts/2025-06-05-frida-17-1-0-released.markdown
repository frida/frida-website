---
layout: news_item
title: 'Frida 17.1.0 Released'
date: 2025-06-05 22:05:33 +0200
author: oleavr
version: 17.1.0
categories: [release]
---

Big release with several exciting improvements!

Firstly, we've switched to ESBuild and typescript-go in the Compiler backend,
resulting in massively improved performance, and reduced our maintenance burden
by no longer having to maintain a bundler. We also added options to configure
the output and bundle format, and support disabling type checks.

Secondly, we now finally ship binaries for Windows/ARM64. This was unblocked by
GitHub making Windows ARM64 hosted runners available to the public.

Special thanks to [@mrmacete][] for plugging Interceptor singleton leaks, and to
[@fesily][] for implementing `Module#enumerateSections()` on Windows, as well as
improving `Module#enumerateImports()` so the `slot` is exposed.

Here's the full list of changes:

- **Compiler improvements**:
  - Switched to ESBuild and typescript-go in the Compiler backend.
  - Added options to configure the output and bundle format, and support
    disabling type checks.
- **Windows/ARM64 support**:
  - CI updated to publish binaries for Windows/arm64.
- **Contributions from our community**:
  - Fixed 32-bit ARM breakpoint logic for Thumb addresses.
  - Plugged Interceptor singleton leaks ([@mrmacete][]).
  - Implemented `Module#enumerateSections()` and wired up import slots on
    Windows ([@fesily][]).

[@mrmacete]: https://twitter.com/bezjaje
[@fesily]: https://github.com/fesily
