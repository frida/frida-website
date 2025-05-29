---
layout: news_item
title: 'Frida 17.0.7 Released'
date: 2025-05-29 17:32:19 +0200
author: oleavr
version: 17.0.7
categories: [release]
---

This release includes a few important fixes:

- **device**: Allow agent sessions to detach before release, to be robust
  against scenarios where an out-of-order detach could lead to an indefinite
  hang at release time. Thanks [@mrmacete][]!
- **darwin**: Dispose module resolver indexes to avoid leaking native modules in
  scenarios where short-lived resolvers are used (for example, on different
  tasks). Thanks [@mrmacete][]!
- **stalker**: Handle blocks without inline cache entries.

[@mrmacete]: https://twitter.com/bezjaje
