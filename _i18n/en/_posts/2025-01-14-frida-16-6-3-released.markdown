---
layout: news_item
title: 'Frida 16.6.3 Released'
date: 2025-01-14 19:35:41 +0100
author: oleavr
version: 16.6.3
categories: [release]
---

The main change in this release is the revival of our Windows injector, which
was broken by the recent Gum.Module refactoring. Other than that we have also
improved the performance of low-level GLib primitives across platforms,
specifically in our patch that implements clean-up of static allocations. This
is needed due to how a Frida-injected payload may have a shorter lifespan than
the process it's injected into.

Enjoy!
