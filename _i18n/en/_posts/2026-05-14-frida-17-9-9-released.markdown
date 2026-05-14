---
layout: news_item
title: 'Frida 17.9.9 Released'
date: 2026-05-14 20:21:24 +0200
author: oleavr
version: 17.9.9
categories: [release]
---

Another quick bug-fix release, focused on GumJS edge-cases and topped off with
some README polish from [@agent-polyblank][]:

- gumjs: Zero NativeCallback return values up-front, and skip copying the FFI
  value on conversion failure. This fixes a regression where uninitialized stack
  data could be handed back to native code, including for struct returns.
- gumjs: Throw an exception in the QuickJS runtime when a struct's array length
  does not match its field count, instead of silently failing conversion.
- gumjs: Handle empty stack traces in the V8 unhandled-exception sink, avoiding
  a crash when an Error originates outside any JavaScript frame.
- readme: Add build and test instructions. Thanks [@agent-polyblank][]!


[@agent-polyblank]: https://github.com/agent-polyblank
