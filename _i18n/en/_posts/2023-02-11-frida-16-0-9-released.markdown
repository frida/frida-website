---
layout: news_item
title: 'Frida 16.0.9 Released'
date: 2023-02-11 10:35:06 +0100
author: oleavr
version: 16.0.9
categories: [release]
---

The main theme of this release is improved support for jailbroken iOS. We now
support iOS 16.3, including app listing and launching. Also included is improved
support for iOS 15, and some regression fixes for older iOS versions.

There are also some other goodies in this release, so definitely check out the
changelog below.

Enjoy!

### Changelog

- darwin: Fix app listing and launching on iOS >= 16. Thanks for the productive
  pair-programming, [@hsorbo][]!
- darwin: Fix crash during early instrumentation of modern dylds.
- darwin: Fix breakpoint conflict in early instrumentation, a regression
  introduced in 16.0.8 as part of improving spawn() performance.
  Thanks [@mrmacete][]!
- package-server-ios: Force xz compression.
- darwin-grafter: Create multiple segments if needed. Thanks [@mrmacete][]!
- interceptor: Flip page protection on Darwin grafted import activation.
  Thanks [@mrmacete][]!
- stalker: Fix handling of ARM LDMIA without writeback.
- darwin: Add query_protection(). Thanks [@mrmacete][]!
- darwin: Avoid kernel task port probing in hardened processes. Thanks [@as0ler][]!
- darwin: Fix Process.modify_thread() reliability.
- darwin: Fix query_hardened() on iOS w/ tweaks enabled. Thanks [@as0ler][]!
- darwin: Make Process.modify_thread() less disruptive.
- darwin: Optimize Process.modify_thread().
- darwin: Add modify_thread().
- arm-writer: Add put_ldmia_reg_mask_wb().
- gumjs: Fix runtime serialization not handling unicode. Thanks [@milahu][]!
- python: Add async variant to RPC calls. Thanks [@yotamN][]!
- python: Add specific signals type hinting for core. Thanks [@yotamN][]!


[@hsorbo]: https://twitter.com/hsorbo
[@mrmacete]: https://twitter.com/bezjaje
[@as0ler]: https://twitter.com/as0ler
[@milahu]: https://github.com/milahu
[@yotamN]: https://github.com/yotamN
