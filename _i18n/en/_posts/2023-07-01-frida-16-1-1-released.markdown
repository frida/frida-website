---
layout: news_item
title: 'Frida 16.1.1 Released'
date: 2023-07-01 06:42:06 +0200
author: oleavr
version: 16.1.1
categories: [release]
---

Only a few changes this time around:

- compiler: Bump frida-compile to 16.3.0, now with TypeScript 5.1.5 and other
  improvements. Among them is a fix by [@hsorbo][] that changes the default
  *moduleResolution* to *Node16*.
- stalker: Add Iterator.get_capstone(), so transformers can use Capstone APIs
  that require the Capstone handle.
- node: Fix RPC message array check. Thanks [@ZachQin][]!


[@hsorbo]: https://twitter.com/hsorbo
[@ZachQin]: https://github.com/ZachQin
