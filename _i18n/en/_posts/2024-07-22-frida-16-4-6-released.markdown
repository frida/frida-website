---
layout: news_item
title: 'Frida 16.4.6 Released'
date: 2024-07-22 21:47:49 +0200
author: oleavr
version: 16.4.6
categories: [release]
---

This release is packing a whole slew of improvements:

- fruity: Use UsbmuxDevice from USB transport if present, so we can reach the
  loopback interface, and for better performance.
- fruity: Handle devices without tunnel support on non-macOS.
- fruity: Expose name from USB transport if present. It has a more descriptive
  name in case of UsbmuxTransport.
- gumjs: Ensure Gum .a is built before building devkit. Thanks
  [@Hexploitable][]!
- gumjs: Generate simpler enum value lookup code.
- spinlock: Consolidate into a single implementation.
- java: Fix art::Thread::DecodeJObject for Android >= 15. Thanks [@esauvisky][]!


[@Hexploitable]: https://twitter.com/Hexploitable
[@esauvisky]: https://github.com/esauvisky
