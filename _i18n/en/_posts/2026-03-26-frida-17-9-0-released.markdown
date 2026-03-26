---
layout: news_item
title: 'Frida 17.9.0 Released'
date: 2026-03-26 20:44:02 +0100
author: oleavr
version: 17.9.0
categories: [release]
---

This release brings a nice mix of quality-of-life improvements and new
capabilities across our Fruity, Droidy, Linux, and packaging layers:

- device: Add `override_option()` for overriding backend-specific options
  when creating a host session, with updates taking effect immediately on
  the next connection if a session is already established.
- fruity: Add `control-endpoint` backend option. Default is `tcp:27042`.
  Only TCP endpoints are supported.
- droidy: Add `control-endpoint` backend option. Default is `tcp:27042`,
  but may be set to any endpoint supported by ADB, such as
  `localabstract:/my-frida-server`.
- android: Skip 32-bit helper on 64-bit only systems, avoiding wasted time
  trying to spawn it.
- linux: Add an eBPF-based spawn gater implementation. Thanks [@NSEcho][]!
- linux: Support injection into group-stopped PIDs.
- gum: Add a tool to package devkits as XCFrameworks. Thanks [@sewerynplazuk][]!
- python: Add a spawn gating example.
- python: Fix the child gating example.

Enjoy!


[@NSEcho]: https://github.com/NSEcho
[@sewerynplazuk]: https://github.com/sewerynplazuk
