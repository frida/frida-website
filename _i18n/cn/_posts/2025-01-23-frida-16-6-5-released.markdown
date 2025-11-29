---
layout: news_item
title: 'Frida 16.6.5 发布'
date: 2025-01-23 20:47:10 +0100
author: oleavr
version: 16.6.5
categories: [release]
---

此版本在 [@kaftejiman][] 和 [@DoranekoSystems][] 的贡献下，为我们的 Linux 和 Android 支持带来了一系列改进和修复。我们还改进了通过网络与 Apple 设备通信的方式。

以下是新内容：

- **linux**: 改进注入器以避免与 memfd 区域进行有风险的代码交换 (感谢 [@kaftejiman][])。Memfd 区域可能不可写，并且与常规区域不同，如果缺少可写位，`ptrace()` 也无济于事。

- **linux**: 放宽注入器对 Android 的 libc 匹配 (感谢 [@kaftejiman][])。这意味着我们仍然可以将它们与绑定挂载的 APEX 匹配。

- **linux**: 针对 Linux/Android 优化 `NativePointer#readVolatile()` (JS) / `gum_memory_read()` (C) (感谢 [@DoranekoSystems][])。通过利用 `process_vm_readv()` (如果内核支持)，我们可以避免解析内存映射。这意味着它现在只比直接访问慢约 1.45 倍，而不是慢 1000 倍以上。

- **fruity**: 支持 `CoreDevice` 的网络 lockdown。我们需要提供远程解锁主机密钥作为 `RSDCheckin` 的一部分。感谢 [@as0ler][] 和 [@mrmacete][] 报告并帮助弄清这个问题。

[@kaftejiman]: https://github.com/kaftejiman
[@DoranekoSystems]: https://github.com/DoranekoSystems
[@as0ler]: https://github.com/as0ler
[@mrmacete]: https://github.com/mrmacete
