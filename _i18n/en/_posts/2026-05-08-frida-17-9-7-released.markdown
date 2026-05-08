---
layout: news_item
title: 'Frida 17.9.7 Released'
date: 2026-05-08 10:40:16 +0200
author: oleavr
version: 17.9.7
categories: [release]
---

Quick bug-fix release with fixes across our Darwin backend, Stalker, and
Compiler:

- darwin: Ensure freshly allocated code pages are included in the page plan when
  debugger mappings are enforced. This fixes Interceptor and Memory.patchCode on
  iOS 26+ on newer Apple devices, where even freshly allocated executable pages
  need a page plan in order to satisfy code-signing checks at execution time.
  Thanks to [@mrmacete][] for the fix.
- stalker-x86: Avoid saving and restoring AVX2 YMM upper halves on Windows 7
  WoW64. Doing so from Stalker's JIT code could corrupt wow64cpu state, so the
  next syscall would crash in wow64cpu!CpupReturnFromSimulatedCode. Since
  fxsave already covers the lower 128 bits, and the x86 Windows ABI does not
  preserve the YMM upper halves across calls, we now skip this on NT 6.1 WoW64.
  Thanks to [@fitblip][] for the fix.
- compiler: Fix a Windows crash when using the Go/cgo backend. We were
  allocating callback strings with mingw's CRT and letting the Vala side free
  them using MSVC's UCRT, which meant different heaps were involved and Windows
  quite reasonably pulled the emergency brake with STATUS_HEAP_CORRUPTION.
  These strings are now freed on the Go side after the callback returns, while
  the Vala side treats them as unowned and duplicates them when needed.


[@mrmacete]: https://x.com/bezjaje
[@fitblip]: https://x.com/fitblip
