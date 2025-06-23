---
layout: news_item
title: 'Frida 17.2.5 Released'
date: 2025-06-23 18:44:36 +0200
author: oleavr
version: 17.2.5
categories: [release]
---

This release brings important fixes and improvements to Frida. Here are the
highlights:

- frida-node: Keep TSFN alive until promise settles, preventing a race condition
  that could cause Node.js to exit early with a "Detected unsettled top-level
  await" warning. Kudos to [@mrmacete][] and [@hsorbo][] for helping track
  this one down.

- frida-node: Simplify `findMatchingDevice()` (co-authored by [@hsorbo][]).

- package-manager: Only bump if explicitly requested.

- package-manager: Fix the `dev` logic.

- docs: Fix Mapper URL in README (thanks to [@cmdlinescan][]).


[@mrmacete]: https://twitter.com/bezjaje
[@hsorbo]: https://twitter.com/hsorbo
[@cmdlinescan]: https://github.com/cmdlinescan
