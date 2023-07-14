---
layout: news_item
title: 'Frida 16.1.3 Released'
date: 2023-07-14 13:18:10 +0200
author: oleavr
version: 16.1.3
categories: [release]
---

Time for a new release, just in time for the weekend:

- server: Add missing entitlement for iOS >= 17. Kudos to [@alexhude][] for
  helping get to the bottom of this one.
- stalker: Improve exclusive store handling on arm and arm64. Instead of
  potentially expanding the current block to include instructions beyond where
  the block would naturally end, we move to a safer approach: Once we encounter
  an exclusive store, we look back at the previously generated blocks to see if
  we can find one with an exclusive load. If we do, we mark this range of blocks
  as using exclusive access. We also invalidate the blocks, so that problematic
  instrumentation can be omitted upon recompilation. To also allow custom
  transformers to adapt their generated code, we introduce
  StalkerIterator.get_memory_access(). Thanks for the fun and productive
  pair-programming, [@hsorbo][]!
- gumjs: Add *StalkerIterator.memoryAccess*, allowing a custom transformer to
  determine what kind of instrumentation is safe to add without disturbing an
  exclusive store operation. Set to either 'open', when “noisy” instrumentation
  such as callouts are safe, or 'exclusive', when such instrumentation is risky
  and may lead to infinite loops. (Due to an exclusive store failing, and every
  subsequent retry also failing.)
- gumjs: Fix CModule bindings for Stalker on arm.
- stalker: Fix crash on invalidation in added slabs.
- arm64-writer: Add put_eor_reg_reg_reg(). Thanks for the fun and productive
  pair-programming, [@hsorbo][]!


[@alexhude]: https://github.com/alexhude
[@hsorbo]: https://twitter.com/hsorbo
