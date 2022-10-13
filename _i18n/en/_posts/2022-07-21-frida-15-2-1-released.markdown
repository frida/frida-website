---
layout: news_item
title: 'Frida 15.2.1 Released'
date: 2022-07-21 09:36:52 +0200
author: oleavr
version: 15.2.1
categories: [release]
---

Two small but significant bugfixes this time around:

- compiler: Ignore irrelevant changes during watch().
- darwin: Improve accuracy of memory range file info. By using
  PROC_PIDREGIONPATHINFO2 when available, so the query is constrained to
  vnode-backed mappings. Kudos to [@i0n1c][] for discovering and tracking
  down this long-standing issue.


[@i0n1c]: https://twitter.com/i0n1c
