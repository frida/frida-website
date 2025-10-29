---
layout: news_item
title: 'Frida 17.4.2 Released'
date: 2025-10-29 16:48:10 +0100
author: oleavr
version: 17.4.2
categories: [release]
---

This week it's time for a batch of Simmy backend improvements. Kudos to
[@hsorbo][] the pair-programming, bringing the following improvements:

- simmy: Implement `get_frontmost_application()`, making it trivial to figure
  out who's currently in the spotlight.
- simmy: Fix the reported `hardware.product` in
  `query_system_parameters()`, e.g. returning `iPhone18,2` instead of
  “iPhone 17 Pro Max”.
- simmy: Wire up application icons.

Enjoy!


[@hsorbo]: https://x.com/hsorbo
