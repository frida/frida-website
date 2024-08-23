---
layout: news_item
title: 'Frida 16.4.5 Released'
date: 2024-07-17 22:43:23 +0200
author: oleavr
version: 16.4.5
categories: [release]
---

Quick bug-fix release to address a few issues:

- xpc-client: Wire up cancellable in request(), to support cancellation of
  remotepairingd requests in our Fruity macOS CoreDevice backend.
- java: Properly handle the Android ART CMC GC strategy. Thanks [@mbricchi][]!
- java: Fix Java.choose() on newer ART APEXes. Thanks [@mbricchi][]!


[@mbricchi]: https://github.com/mbricchi
