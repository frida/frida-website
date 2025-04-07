---
layout: news_item
title: 'Frida 16.7.8 Released'
date: 2025-04-07 10:09:08 +0200
author: oleavr
version: 16.7.8
categories: [release]
---

Quick bug-fix release to fix a crash on Apple OSes.

Thanks to [@mrmacete][] for contributing the following fix:

- darwin: Fix module type in find_module_by_address.
  This was a type confusion causing subtle crashes.

[@mrmacete]: https://twitter.com/bezjaje
