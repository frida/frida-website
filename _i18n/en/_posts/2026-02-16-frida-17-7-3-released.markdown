---
layout: news_item
title: 'Frida 17.7.3 Released'
date: 2026-02-16 22:45:51 +0100
author: oleavr
version: 17.7.3
categories: [release]
---

Quick follow-up release with a handful of Linux syscall-tracer improvements and
fixes:

- syscall-tracer: Decode timespec values. Recognize timespec pointer arguments
  and decode them into structured values instead of opaque byte arrays.
  Supports both `__kernel_timespec` and `old_timespec32` layouts.
- syscall-tracer: Fix raw attachment lifetime. The GVariant was previously
  created from data freed before return, leaving it with a dangling pointer.
- syscall-tracer: Fix multi-attachment parsing by encoding how much space is
  reserved for each attachment.
