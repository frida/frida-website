---
layout: news_item
title: 'Frida 17.9.8 Released'
date: 2026-05-11 13:22:58 +0200
author: oleavr
version: 17.9.8
categories: [release]
---

Here's a quick release with a GumJS bug-fix, a small API improvement, and a
compiler type bump. Big thanks to vfsfitvnm and Francesco Tamagni for the
GumJS improvements:

- gumjs: Fix `NativeCallback` returning structs. The libffi closure result
  path for `FFI_TYPE_STRUCT` was unimplemented and would hit
  `g_assert_not_reached()`. We now walk struct return values, including nested
  structs, and copy each leaf field's natural bytes into the return buffer.
  The QuickJS and V8 callback invokers also size their temporary return
  buffer from `rtype->size`, so structs fit as expected. Thanks to
  [@vfsfitvnm][] for the fix.
- gumjs: Extend `Memory.alloc()` with an optional `protection` field on the
  options object, defaulting to `"rw"` to preserve existing behavior. This
  makes it possible to allocate page-aligned executable memory in environments
  where memory cannot be flipped from rw to rx, such as non-jailbroken
  iOS 26+. Thanks to [@mrmacete][].
- compiler: Bump `@types/frida-gum` to 19.1.0.


[@vfsfitvnm]: https://github.com/vfsfitvnm
[@mrmacete]: https://x.com/bezjaje
