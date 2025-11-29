---
layout: news_item
title: 'Frida 16.6.4 发布'
date: 2025-01-17 16:49:19 +0100
author: oleavr
version: 16.6.4
categories: [release]
---

此版本带来了重要的修复和改进：

- **objc**: 处理扩展块类型编码 (感谢 [@mrmacete][])。
- **module**: 恢复了之前对 `NativeModule` 生命周期的优化，因为我们 GLib 补丁中的潜在性能问题已得到解决。
- **darwin**: 修复了当提供别名时 `Module.load()` 可能失败的问题。在 macOS >= 13 上，我们现在使用 `_dyld_get_dlopen_image_header()` 按地址解析模块。
- **linux**: 恢复了对 ARM BE8 的支持，恢复了与大端 ARM 系统的兼容性。

[@mrmacete]: https://github.com/mrmacete
