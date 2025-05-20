---
layout: news_item
title: 'Frida 17.0.2 Released'
date: 2025-05-20 22:41:03 +0200
author: oleavr
version: 17.0.2
categories: [release]
---

This release brings a few bug fixes:

- **Compiler**: Updated frida-compile and frida-fs to the latest versions.
- **gum**: Fixed forgotten diet bits related to GObject, now that it's back to
  being a required library.
- **gumjs**: Fixed an assigned-but-not-used warning when building without
  assertions.
