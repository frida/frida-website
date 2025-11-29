---
layout: news_item
title: 'Frida 17.2.6 发布'
date: 2025-06-27 16:00:01 +0200
author: oleavr
version: 17.2.6
categories: [release]
---

我们很高兴宣布 Frida 17.2.6，包含两个重要修复：

- **buffer**: 修复 `read_fixed_string()` 中的 `max_length`。

  `max_length` 现在被正确地限制在请求的大小和缓冲区的大小之内。

  感谢 [@mrmacete][]！

- **agent**: 在模拟领域禁用 Exceptor。

  Exceptor 需要 hook `signal()` 和 `sigaction()`，但它们在 libc 中。
  这导致 `gum_mprotect()` 中止，因为它无法更改 libc 的只读映射。此修复防止了在 Android 14 和 15 AVD 上使用 `frida-server` 或 `frida-inject` 时观察到的崩溃。

  感谢 [@ptrstr][]！


[@mrmacete]: https://twitter.com/bezjaje
[@ptrstr]: https://github.com/ptrstr
