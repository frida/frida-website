---
layout: news_item
title: 'Frida 17.1.3 Released'
date: 2025-06-07 13:32:40 +0200
author: oleavr
version: 17.1.3
categories: [release]
---

This release brings a series of improvements and bug fixes across various
components. Here are the highlights:

- Renamed conflicting Go symbols in the Compiler backend to avoid conflicts
  when linking into a Go binary. This ensures compatibility when integrating
  with Go projects.
- On Linux, fixed issues related to the thread list anchor to prevent false
  positives. Previously, the anchor might be incorrectly added to the thread
  list, leading to incorrect behavior.
- Corrected the QuickJS big-endian bytecode check in both the gadget and
  GumJS. The previous check was incorrect on big-endian systems.
- Added version defines and macros to the API, providing more explicit version
  information for developers.
