---
layout: news_item
title: 'Frida 16.2.5 Released'
date: 2024-05-21 12:50:43 +0200
author: oleavr
version: 16.2.5
categories: [release]
---

A quick bug-fix release with three improvements:

- ci: Fix the frida-node prebuild loop for macOS, so we generate prebuilds for
  all targets, not just the first one.
- node: Avoid relying on package-lock.json, to support fallback build when
  prebuild is missing.
- android: Set DexFile to read-only in Java.registerClass(). As of Android 14,
  apps with targetSdk >= 34 are not allowed to have writable permissions on
  dynamically loaded Dex files. Thanks [@pandasauce][]!

Enjoy!


[@pandasauce]: https://github.com/pandasauce
