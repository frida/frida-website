---
layout: news_item
title: 'Frida 16.1.2 Released'
date: 2023-07-11 17:44:02 +0200
author: oleavr
version: 16.1.2
categories: [release]
---

Time for a new release to refine a few things:

- darwin: Fix Stalker.follow() regression where ongoing system calls would get
  brutally interrupted, typically resulting in the target crashing. Thanks for
  the pair-programming, [@hsorbo][]!
- gumjs: Implement the WeakRef API for QuickJS.
- compiler: Bump @types/frida-gum to 18.4.0.


[@hsorbo]: https://twitter.com/hsorbo
