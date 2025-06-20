---
layout: news_item
title: 'Frida 17.2.4 Released'
date: 2025-06-20 15:45:42 +0200
author: oleavr
version: 17.2.4
categories: [release]
---

Another quick bug-fix release to improve our package manager, where [@hsorbo][]
and I have been hard at work. Here's what's new:

- package-manager: Fix dependency install deadlock. A deadlock could occur
  when a package's sub-dependency was also a dependency of another package
  higher up in the installation stack. The sub-dependency would wait for the
  higher-level package to be physically installed, but that package would not
  complete its own installation until its sub-dependencies were resolved,
  creating a circular wait.
- package-manager: Improve manifest handling to get us closer to npm's
  behavior. (Co-authored by [@hsorbo][].)
- package-manager: Improve progress reporting.

[@hsorbo]: https://twitter.com/hsorbo
