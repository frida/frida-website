---
layout: news_item
title: 'Frida 17.2.1 Released'
date: 2025-06-19 21:03:53 +0200
author: oleavr
version: 17.2.1
categories: [release]
---

Another quick bug-fix release, addressing several issues uncovered since the last
release:

- compiler: On Android, made the backend a shared library to avoid dynamic linking
  issues due to thread-local storage.
- python: Exposed `PackageManager.registry` property.
- python: Fixed missing toplevel counter logic for `Compiler`, `PackageManager`,
  and `FileMonitor`, ensuring signal emissions work correctly.
- python: Added `__repr__` methods to `PackageManager` types for better
  debugging.
- core: Fixed build issue when libsoup is used as a subproject.
