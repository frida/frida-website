---
layout: news_item
title: 'Frida 1.6.4 Released'
date: 2014-10-19 04:04:00 +0100
author: oleavr
version: 1.6.4
categories: [release]
---

It's time for a bug fix release!

Stalker improvements:

- The engine no longer pre-allocates a fixed chunk of 256 MB per thread being
  traced, and now grows this dynamically in a reentrancy-safe manner.
- Eliminated a bug in the cache lookup logic where certain blocks would always
  result in a cache miss. Those blocks thus got recompiled every time they
  were about to get executed, slowing down execution and clogging up the cache
  with more and more entries, and eventually running out of memory.
- Relocation of RIP-relative `cmpxchg` instruction is now handled correctly.

Better Dalvik integration (Android):

- App's own classes can now be loaded.
- Several marshalling bugs have been fixed.

Script runtime:

- More than one NativeFunction with the same target address no longer results
  in use-after-free.

Also, [CryptoShark 0.1.2](https://github.com/frida/cryptoshark) is out,
with an upgraded Frida engine and lots of performance improvements so the GUI
is able to keep up with the Stalker. Go get it while it's hot!
