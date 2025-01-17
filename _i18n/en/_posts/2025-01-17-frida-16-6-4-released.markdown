---
layout: news_item
title: 'Frida 16.6.4 Released'
date: 2025-01-17 16:49:19 +0100
author: oleavr
version: 16.6.4
categories: [release]
---

This release brings important fixes and improvements:

- **objc**: Handle extended block type encoding (thanks to [@mrmacete][]).
- **module**: Reverted the previous optimization of `NativeModule` lifecycle,
  as the underlying performance issue in our GLib patch has been addressed.
- **darwin**: Fixed an issue where `Module.load()` could fail when provided
  with an alias. On macOS >= 13, we now use `_dyld_get_dlopen_image_header()`
  to resolve modules by address.
- **linux**: Revived support for ARM BE8, restoring compatibility with
  big-endian ARM systems.

[@mrmacete]: https://github.com/mrmacete
