---
layout: news_item
title: 'Frida 17.4.1 Released'
date: 2025-10-24 15:25:28 +0200
author: oleavr
version: 17.4.1
categories: [release]
---

A small but tasty follow-up release to keep the momentum going:

- android: Bump `frida-java-bridge` in `system-server`, bringing in the latest
  stability improvements:
  - android: Handle static trampoline fixups, so we roll back each ArtMethod to
    its previous entrypoint, to avoid hooks being bypassed.
  - android: Synchronize ArtMethod class field post GC, so our replacement
    ArtMethod instances don't go stale, and cause undefined behavior.
  Thanks for the pair-programming, [@hsorbo][].
- devkit-assets: Upgrade GumJS example to the new Frida 17 GumJS API. Thanks to
  [@Hexploitable][] for making this happen.
- freebsd: Wire up PTY support so spawn/attach operations depending on a
  controlling terminal now work out of the box.

Enjoy!


[@hsorbo]: https://x.com/hsorbo
[@Hexploitable]: https://x.com/Hexploitable
