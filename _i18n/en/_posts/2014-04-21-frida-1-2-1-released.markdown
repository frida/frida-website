---
layout: news_item
title: 'Frida 1.2.1 Released'
date: 2014-04-21 16:00:00 +0100
author: oleavr
version: 1.2.1
categories: [release]
---

Had some fun tracing Apple's crypto APIs, which lead to the discovery of
a few bugs. So here's 1.2.1 bringing some critical ARM-related bugfixes:

-   ARM32: Fix crashes caused by register clobber issue in V8 on ARM32 due to
    an ABI difference regarding `r9` in Apple's ABI compared to AAPCS.
-   ARM32: Fix ARM32/Thumb relocator branch rewriting for immediate same-mode
    branches.
-   ARM64: Improve ARM64 relocator to support rewriting `b` and `bl`.
