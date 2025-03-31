---
layout: news_item
title: 'Frida 16.7.4 Released'
date: 2025-03-31 21:23:04 +0200
author: oleavr
version: 16.7.4
categories: [release]
---

This release includes several improvements and fixes, including support for
remote services and channels, along with various other enhancements:

- **Core**:
  - Added support for remote services and channels in host sessions, allowing
    `ControlService`/`frida-server` to serve service sessions and channels.
  - Fixed session logic for remote devices in `ControlService`.

- **Compiler**:
  - Bumped `frida-compile` and `@types/frida-gum` to the latest versions.

- **Python Bindings**:
  - Fixed `IOStream.read_all()` end-of-stream handling.

As always, happy hacking!
