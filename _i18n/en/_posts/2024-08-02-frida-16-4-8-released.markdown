---
layout: news_item
title: 'Frida 16.4.8 Released'
date: 2024-08-02 14:05:27 +0200
author: oleavr
version: 16.4.8
categories: [release]
---

Quick bug-fix release to further improve our Fruity backend:

- lockdown-client: Bubble up CONNECTION_CLOSED error. Thanks [@hsorbo][]!
- fruity: Make find_usbmux_device() non-throwing. Thanks [@hsorbo][]!
- fruity: Guard against lockdown open.- ->close loop.
- fruity: Fix invalidation of closed lockdown client. Thanks [@hsorbo][]!


[@hsorbo]: https://twitter.com/hsorbo
