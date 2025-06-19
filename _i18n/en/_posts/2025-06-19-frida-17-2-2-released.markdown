---
layout: news_item
title: 'Frida 17.2.2 Released'
date: 2025-06-19 23:25:55 +0200
author: oleavr
version: 17.2.2
categories: [release]
---

We're back with a quick bug-fix release:

- package-manager: Fixed the lockfile up-to-date path.
- package-manager: Only report installed packages. The top-level packages that
  were left untouched are no longer included. Also simplified the `install()`
  logic.
