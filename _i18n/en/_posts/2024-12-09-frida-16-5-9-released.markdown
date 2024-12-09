---
layout: news_item
title: 'Frida 16.5.9 Released'
date: 2024-12-09 00:52:39 +0100
author: oleavr
version: 16.5.9
categories: [release]
---

Oops, software is hard! Here's another quick release to address an issue we
missed earlier today.

We've fixed an issue with our Meson build scripts where the modulemap
dependencies were not correctly specified after the latest changes in
frida-core. Specifically, `core_public_h` is now a custom target index, so we
can't use it directly anymore. Instead, we now depend on its parent,
`core_api`.

Special thanks to [@hsorbo][] for co-authoring this fix.

[@hsorbo]: https://twitter.com/hsorbo
