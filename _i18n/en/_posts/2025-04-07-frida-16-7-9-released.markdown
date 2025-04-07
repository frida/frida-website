---
layout: news_item
title: 'Frida 16.7.9 Released'
date: 2025-04-07 19:32:56 +0200
author: oleavr
version: 16.7.9
categories: [release]
---

Turns out software is hard! On the same day as our previous release, we've rolled
out another quick bug-fix release to address some issues that came up. Huge
thanks to [@mrmacete][] for his contribution. Here's what's new:

- **channel**: Break read loop on empty buffer. (Thanks [@mrmacete][]!)
- **device-manager**: Fix teardown logic, where we would also `stop()` the
  `HostSessionService` in cases where it hadn't been `start()`ed.

[@mrmacete]: https://twitter.com/bezjaje
