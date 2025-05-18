---
layout: news_item
title: 'Frida 17.0.1 Released'
date: 2025-05-17 23:48:23 +0200
author: oleavr
version: 17.0.1
categories: [release]
---

Surprise! We're back with a quick patch release on the same day as 17.0.0.
Turns out software is hard!

This release includes the following fixes:

- **Core**: Updated interface versions to match the major version.
- **Darwin**: Bumped `frida-objc-bridge` to version 8.0.4.
- **Android**: Bumped `frida-java-bridge` to version 7.0.1.
- **frida-node**: Fixed the return type of `Device.openChannel()` to avoid
  exposing implementation details that we might want to change in the future.
