---
layout: news_item
title: 'Frida 17.2.9 Released'
date: 2025-07-02 12:59:19 +0200
author: oleavr
version: 17.2.9
categories: [release]
---

This time we're bringing you preliminary iOS 26 support, and a bug-fix for our
Node.js bindings:

- **fruity**: Added support for injecting the gadget on iOS targets where
  debugger mappings are enforced (iOS 26) and we can't flip the memory
  protection back to executable from inside the target process. In such cases,
  the gadget configuration will have `code_signing` set to `required` until
  Interceptor supports enforced debugger mappings. Thanks [@mrmacete][]!

- **device**: Fixed an issue where the `stdio` option wasn't passed through
  `spawn()`, causing child processes to always inherit stdio. Co-authored by
  [@hsorbo][].


[@mrmacete]: https://twitter.com/bezjaje
[@hsorbo]: https://twitter.com/hsorbo
