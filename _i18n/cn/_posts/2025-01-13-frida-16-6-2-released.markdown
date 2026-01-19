---
layout: news_item
title: 'Frida 16.6.2 发布'
date: 2025-01-13 22:20:51 +0100
author: oleavr
version: 16.6.2
categories: [release]
---

另一轮改进和修复，以增强 Frida 的稳定性和性能，感谢 [@mrmacete][] 的宝贵反馈。以下是此版本的新内容：

- **gumjs**: 通过使用空闲源推迟 unref 来修复 `Module` 终结器中的崩溃。这避免了由我们的 QuickJS 挂起/恢复补丁不支持从终结器使用引起的问题，并且还避免了在大容量模块销毁期间挂起/恢复 JS 执行的开销。更好的长期解决方案将涉及引入 `ModuleObserver` 来管理 `Module` 生命周期并在添加或删除模块时发出信号。

- **module**: 通过对所有 `Module` 对象使用单个锁来加速 `NativeModule` 生命周期。此更改提高了性能，一旦 GLib 静态分配清理补丁增强为使用更合适的互斥锁跟踪数据结构，将重新审视此更改。

[@mrmacete]: https://github.com/mrmacete
