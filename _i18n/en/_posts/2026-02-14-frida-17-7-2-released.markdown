---
layout: news_item
title: 'Frida 17.7.2 Released'
date: 2026-02-14 10:52:20 +0100
author: oleavr
version: 17.7.2
categories: [release]
---

Quick follow-up release with a handful of fixes and cleanups in our Variant and
XPC service layers:

- python: Add support for casting to uint64 Variant.
- node: Stop accepting redundant uint64 Variant casts. Use BigInt when creating
  uint64 GVariant values.
- node: Plug a leak in the Variant cast logic's error handling.
- xpc-service: Drop support for redundant casts.
