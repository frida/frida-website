---
layout: news_item
title: 'Frida 15.2.2 Released'
date: 2022-07-21 20:01:25 +0200
author: oleavr
version: 15.2.2
categories: [release]
---

Two more improvements, just in time for the weekend:

- darwin: Always host system session locally. In this way we avoid needing to
  write our frida-helper to a temporary file and spawn it just to use the system
  session (PID 0).
- darwin: Rework frida-helper IPC to avoid Mach ports. This means we avoid
  crashing on recent versions of macOS. Kudos to co-author [@hsorbo][] for the
  productive pair-programming on this one!


[@hsorbo]: https://twitter.com/hsorbo
