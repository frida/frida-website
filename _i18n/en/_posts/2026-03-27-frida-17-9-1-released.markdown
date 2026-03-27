---
layout: news_item
title: 'Frida 17.9.1 Released'
date: 2026-03-27 11:36:54 +0100
author: oleavr
version: 17.9.1
categories: [release]
---

Quick bug-fix release with the following improvement:

- package-manager: Fix semver pre-release overflow, where numeric pre-release
  identifiers like `"202508252028"` would fail validation because `parse_uint()`
  rejects values beyond `UINT32_MAX`. The same overflow also affected version
  comparison, which used `uint`.
  Validation now follows the semver rule that numeric identifiers must not have
  leading zeros, and comparison now uses length-prefixed string comparison so
  arbitrarily large numeric identifiers are handled correctly.
