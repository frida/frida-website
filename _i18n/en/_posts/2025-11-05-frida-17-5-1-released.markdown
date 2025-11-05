---
layout: news_item
title: 'Frida 17.5.1 Released'
date: 2025-11-05 18:59:20 +0100
author: oleavr
version: 17.5.1
categories: [release]
---

Fresh out of the oven: Frida 17.5.1! 🍞

This release includes one important bug fix:

- **darwin-mapper**: Added validation for local shared cache lookups. Symbols
  that *appear* to live in the cache can no longer resolve to a dylib lurking
  outside it (e.g. an introspection build of `libsystem_pthread.dylib`). Huge
  thanks to [@hsorbo][] for pairing on the investigation!

Enjoy hacking! 🧠💥


[@hsorbo]: https://x.com/hsorbo
