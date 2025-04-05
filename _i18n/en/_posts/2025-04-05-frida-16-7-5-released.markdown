---
layout: news_item
title: 'Frida 16.7.5 Released'
date: 2025-04-05 08:52:28 +0200
author: oleavr
version: 16.7.5
categories: [release]
---

We're excited to announce Frida 16.7.5, which brings improvements to our
build system and API, as well as critical fixes for Darwin platforms.
Here's what's new:

- **Darwin**: Fix double free in `find_module_by_address`. (Thanks to
  [@mrmacete][].)

- **Darwin**: Update thread list pointer carving to support recent iOS
  versions. On these versions, the thread list pointer within
  `pthread_from_mach_thread_np()` is referenced via `ADRP + LDR` instead
  of `ADRP + ADD`. (Thanks to [@mrmacete][] for the contribution.)

- **API**: Fix VAPI entries for sealed classes.

- **API**: Remove some accidentally exposed types.

- **API**: Seal classes not meant to be subclassed, preventing unintended
  subclassing.

- **Build System**: Provide `Gio-2.0.gir` for convenience, so users won't
  need any GObject Introspection packages installed when building language
  bindings and consuming Frida as a subproject.

- **Build System**: Fix `frida_girdir` for the uninstalled case. It now
  correctly points to the directory containing the refined `.gir` files,
  not the raw ones from the Vala compiler.


[@mrmacete]: https://twitter.com/bezjaje
