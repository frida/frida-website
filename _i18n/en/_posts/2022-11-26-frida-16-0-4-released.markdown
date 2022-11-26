---
layout: news_item
title: 'Frida 16.0.4 Released'
date: 2022-11-26 01:35:58 +0100
author: oleavr
version: 16.0.4
categories: [release]
---

Here's a brand new release just in time for the weekend! 🎉 A few critical
stability fixes this time around.

Enjoy!

### Changelog

- gumjs: Fix use-after-free in the V8 JobState logic. Kudos to [@pancake][] for
  reporting and helping track this one down!
- android: Fix racy Zygote and system_server instrumentation. Thanks for the fun
  and productive pair-programming, [@hsorbo][]!
- submodules: Add frida-go. Thanks [@lateralusd][]!


[@pancake]: https://twitter.com/trufae
[@hsorbo]: https://twitter.com/hsorbo
[@lateralusd]: https://github.com/lateralusd
