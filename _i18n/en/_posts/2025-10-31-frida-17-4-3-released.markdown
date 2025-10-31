---
layout: news_item
title: 'Frida 17.4.3 Released'
date: 2025-10-31 20:24:19 +0100
author: oleavr
version: 17.4.3
categories: [release]
---

Spooky season brought a small batch of fixes and improvements:

- simmy: Gracefully degrade features that rely on injecting into SpringBoard
  whenever System Integrity Protection (SIP) is enabled. This means that
  `get_frontmost_application()` and icon retrieval now fall back rather than
  exploding.

- simmy: Fix enumeration of installed apps when a subset of bundle IDs was
  requested. Hat-tip to [@hsorbo][] for the assist!

- docs: Update the README’s Apple-certificate section to reflect the current
  reality. Thanks to [@gemesa][] for spotting and fixing the outdated bits!

Enjoy, and happy hacking!


[@hsorbo]: https://x.com/hsorbo
[@gemesa]: https://github.com/gemesa
