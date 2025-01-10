---
layout: news_item
title: 'Frida 16.6.0 Released'
date: 2025-01-09 13:18:51 +0100
author: oleavr
version: 16.6.0
categories: [release]
---

Pleased to announce Frida 16.6.0, featuring significant improvements to module
symbol handling, performance enhancements, and bug fixes.

Here are the highlights:

- **module**: Turn Module APIs into instance methods, so multiple queries can be
  performed efficiently. This was previously only modelled as such at the
  JavaScript (GumJS) level, where such a JS object would have the module's path
  as a string, passed to each query, such as `enumerateExports()`. The
  underlying C API is now also modelled the same way.
- **gumjs**: Add `findSymbolByName()` and `getSymbolByName()` methods.
  Provide direct, native lookups for symbols by name instead of enumerating
  all symbols and filtering them in JavaScript.
- **module**: Optimize `find_symbol_by_name()` fallback. When the Module
  implementation lacks an optimized symbol lookup method, build a sorted index
  and binary-search it.
- **elf-module**: Use MiniDebugInfo if no symbols found. When
  `enumerate_symbols()` encounters an ELF with no symbols in memory,
  instantiate an offline `ElfModule` instance and parse the `.gnu_debugdata`
  section. Decompress the embedded ELF and reuse its symbols as a fallback.
- Port to the new `Gum.Module` API. Transitioned to instance methods to allow
  multiple queries to be performed efficiently.
- Drop support for running without GObject. The footprint savings were minimal
  and didn't justify the added complexity and reduced code readability.
- **gumjs**: Fix V8 `NativeCallback` use-after-free (non-Interceptor), where
  the `CpuContext` was too narrowly scoped.

As always, happy hacking!
