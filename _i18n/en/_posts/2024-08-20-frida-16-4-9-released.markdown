---
layout: news_item
title: 'Frida 16.4.9 Released'
date: 2024-08-20 21:50:56 +0200
author: oleavr
version: 16.4.9
categories: [release]
---

Quick bug-fix release to address some issues:

- tunnel-interface-observer: Fix start() crash on i/tvOS, when
  SCDynamicStoreCopyKeyList() fails. Thanks [@mrmacete][]!
- darwin-mapper: Initialize TLV before constructors. Thanks [@jiska][]!
- darwin-mapper: Fix TLV init runtime code for arm64. Thanks [@jiska][]!
- arm64-writer: Fix encoding of UBFM and LS{L,R}. Thanks [@jiska][]!


[@mrmacete]: https://twitter.com/bezjaje
[@jiska]: https://chaos.social/@jiska
