---
layout: news_item
title: 'Frida 17.6.2 Released'
date: 2026-01-23 22:31:34 +0100
author: oleavr
version: 17.6.2
categories: [release]
---

This release brings a set of stability and compatibility improvements across
multiple platforms and components:

- fruity: Fix PortableCoreDevice flush infinite loop, by reviving the call to
  `handle_events_completed` during FLUSHING state so that `pending_usb_ops` can
  get emptied eventually. Thanks to [@mrmacete][].
- compiler: Rename conflictful Go symbols. Thanks to [@NSEcho][].
- compiler: Load backend through memfd with fallback, so we retain the benefits
  of avoiding temporary files when possible.
- linux: Fix system session when memfd is restricted (observed in the Termux
  environment on Android).
- elf-module: Make {Section,Symbol}Details boxed, enabling bindings to pass/own
  them safely by adding ref/copy/free semantics and updating Vala bindings.
- process: Make ThreadDetails free func NULL-safe.
- darwin-module: Make Image free function NULL-safe.
- linux: Initialize variable to silence warning where the compiler can't prove
  the out-argument is initialized when returning TRUE.
- linux: Handle interpreter-exec wrapper binaries (e.g. `ld.so <program>`), by
  detecting AT_BASE == 0 and recovering the real program and interpreter
  mappings from /proc/self/maps.

[@mrmacete]: https://x.com/bezjaje
[@NSEcho]: https://github.com/NSEcho
