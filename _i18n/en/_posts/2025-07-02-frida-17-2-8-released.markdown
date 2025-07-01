---
layout: news_item
title: 'Frida 17.2.8 Released'
date: 2025-07-02 00:09:26 +0200
author: oleavr
version: 17.2.8
categories: [release]
---

Quick bug-fix release to address an issue affecting our Windows users:

- **package-manager**: Fix broken `#if` on Windows. The incorrect preprocessor
  directive was causing build failures when compiling on Windows platforms.
