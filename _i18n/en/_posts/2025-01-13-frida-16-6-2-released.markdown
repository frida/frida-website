---
layout: news_item
title: 'Frida 16.6.2 Released'
date: 2025-01-13 22:20:51 +0100
author: oleavr
version: 16.6.2
categories: [release]
---

Another round of improvements and fixes to enhance Frida's stability and
performance, thanks to invaluable feedback from [@mrmacete][]. Here's what's new
in this release:

- **gumjs**: Fix crash in `Module` finalizers by deferring unref using an idle
  source. This avoids issues caused by our QuickJS suspend/resume patch not
  supporting usage from finalizers, and also avoids the overhead of
  suspending/resuming JS execution during high-volume module destruction. A
  better long-term solution will involve introducing a `ModuleObserver` to
  manage `Module` lifecycles and emit signals when modules are added or removed.

- **module**: Speed up `NativeModule` lifecycle by using a single lock for all
  `Module` objects. This change improves performance and will be revisited once
  the GLib static allocation cleanup patch is enhanced to use a more suitable
  data structure for mutex tracking.

[@mrmacete]: https://github.com/mrmacete
