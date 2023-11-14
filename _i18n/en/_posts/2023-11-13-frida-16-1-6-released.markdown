---
layout: news_item
title: 'Frida 16.1.6 Released'
date: 2023-11-13 22:43:57 +0100
author: oleavr
version: 16.1.6
categories: [release]
---

Just a quick bug-fix release to roll back two of the Interceptor/Relocator arm64
changes that went into the previous release. Turns out that these need some more
refinement before they can land, so we will roll them back for now.

### Changelog

- Revert "relocator: Improve scratch register strategy on arm64".
- Revert "interceptor: Relocate tiny targets on arm64".
- stalker: Allow transformer to skip calls on arm64.
