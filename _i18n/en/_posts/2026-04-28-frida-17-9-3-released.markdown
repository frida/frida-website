---
layout: news_item
title: 'Frida 17.9.3 Released'
date: 2026-04-28 16:54:56 +0200
author: oleavr
version: 17.9.3
categories: [release]
---

Another quick bug-fix release, because software is hard and apparently enjoys
reminding us of that more than once a day.

- asset-location: Fix installed-asset path resolution when frida-core is
  statically linked. `AssetLocation.detect()` may run from the host executable,
  so binaries installed under `bin/` or `sbin/` could make us look for assets
  relative to that directory instead of the configured libdir, e.g.
  `/usr/sbin/frida-1.0/...` instead of `/usr/lib/frida-1.0/...`. We now redirect
  through the Meson-configured libdir, handle `sbin` too, and avoid appending
  `<arch>` on Darwin where fat binaries mean the default asset path has no
  architecture component.
