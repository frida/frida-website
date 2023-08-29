---
layout: news_item
title: 'Frida 16.1.4 Released'
date: 2023-08-29 15:58:08 +0200
author: oleavr
version: 16.1.4
categories: [release]
---

Some exciting improvements this time around:

- ios: Fix spawn() on iOS 17. Thanks [@hsorbo][]!
- ios: Add support for rootless systems. Thanks for the pair-programming,
  [@hsorbo][]!
- android: Fix dynamic linker compatibility regression. Thanks for the
  pair-programming, [@hsorbo][]! Kudo to [@getorix][] for reporting.
- gumjs: Add Worker API, so heavy processing can be moved to a background
  thread, allowing hooks to be handled in a timely manner. Only implemented in
  the QuickJS runtime for now. Kudos to [@mrmacete][] for tracking down and
  fixing last-minute bugs in the implementation.
- linux: Improve error-handling when trying to attach to processes that are
  near death.


[@hsorbo]: https://x.com/hsorbo
[@getorix]: https://x.com/getorix
[@mrmacete]: https://x.com/bezjaje
