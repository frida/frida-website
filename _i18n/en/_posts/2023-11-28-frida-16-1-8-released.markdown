---
layout: news_item
title: 'Frida 16.1.8 Released'
date: 2023-11-28 22:06:07 +0100
author: oleavr
version: 16.1.8
categories: [release]
---

Three exciting changes this time around:

- process: Add *get_main_module()*, exposed to JavaScript as
  *Process.mainModule*. Useful when needing to know which module represents the
  main executable of the process. In the past this was typically accomplished
  by enumerating the loaded modules and assuming that the first one in the list
  is the one. This is no longer the case on the latest Apple OSes, so we now
  provide an efficient and portable solution with this new API. Thanks
  [@mrmacete][]!
- compiler: Bump @types/frida-gum to 18.5.0, now with typings for recent API
  additions.
- barebone: Fix compatibility with latest Corellium.


[@mrmacete]: https://x.com/bezjaje
