---
layout: news_item
title: 'Frida 16.6.6 发布'
date: 2025-01-27 20:54:40 +0100
author: oleavr
version: 16.6.6
categories: [release]
---

此版本带来了重要的错误修复，并优化了 Linux 和 Android 上的易失性内存写入。非常感谢 [@DoranekoSystems][] 的贡献。

- **fruity**: 修复了上一版本中引入的 CoreDevice 上的 lockdown 回归，其中 `RSDCheckin` 现在包含一个 `EscrowBag` 以支持具有 `com.apple.crashreportmover` 等服务的网络 lockdown。结果发现这破坏了对某些缺乏与 `AppleKeyStoreUserClient` 对话权限的服务的支持。我们现在维护一个此类服务的列表，以便为它们省略 `EscrowBag`。感谢 [@as0ler][] 报告并帮助排除故障。

- **darwin**: 修复 Apple Silicon 上的 sysroot 检测，以便我们可以正确解析 Simulator 进程内的模块。感谢 [@stacksmashing][] 的报告。

- **linux**: 针对 Linux/Android 优化 `NativePointer#writeVolatile()` (JS) / `gum_memory_write()` (C) (感谢 [@DoranekoSystems][])。通过利用 `process_vm_writev()` (如果内核支持)，我们可以避免解析内存映射。这意味着它现在的速度快了数千倍。

[@DoranekoSystems]: https://github.com/DoranekoSystems
[@as0ler]: https://github.com/as0ler
[@stacksmashing]: https://x.com/ghidraninja
