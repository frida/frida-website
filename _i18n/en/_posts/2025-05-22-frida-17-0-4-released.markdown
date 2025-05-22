---
layout: news_item
title: 'Frida 17.0.4 Released'
date: 2025-05-22 21:39:44 +0200
author: oleavr
version: 17.0.4
categories: [release]
---

This release brings improvements to the Compiler implementation, underpinning
the frida-compile CLI tool, part of frida-tools. Here are the changes:

- Upgraded to **frida-compile 18**, now with TypeScript 5.8.3, latest frida-fs,
  etc.
- Fixed asset bundling logic on Windows, where virtual paths were stored with
  the wrong path separator.
