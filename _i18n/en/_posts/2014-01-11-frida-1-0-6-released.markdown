---
layout: news_item
title: 'Frida 1.0.6 Released'
date: 2014-01-11 23:00:00 +0100
author: oleavr
version: 1.0.6
categories: [release]
---

This release simplifies the licensing and fixes bugs reported by the community
since the HN launch.

Primarily:
- Relicense remaining GPLv3+ Frida components to LGPLv2.1+ (same as frida-gum).
- Tracer works on 64-bit with function addresses in the upper range
- Linux build links with Frida's own libraries instead of the build machine's
  corresponding libraries.
