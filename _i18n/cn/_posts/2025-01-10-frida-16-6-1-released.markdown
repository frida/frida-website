---
layout: news_item
title: 'Frida 16.6.1 发布'
date: 2025-01-10 02:04:19 +0100
author: oleavr
version: 16.6.1
categories: [release]
---

一个包含一些重要修复和改进的新版本：

- **gumjs**: 在取消引用模块时放弃 JS 锁。以避免在 `dispose()` 释放缓存句柄的情况下发生死锁。这种操作通常需要获取运行时链接器锁。另一个线程可能在等待 JS 锁时已经持有该锁。发生这种情况的一个常见场景是代理向运行时链接器注册一个回调，每当加载或卸载模块时都会调用该回调。

  感谢 [@mrmacete][] 的报告。

- **agent**: 在版本脚本中排除 OS/arch 符号。较新的工具链，例如 FreeBSD 14.2 上的默认工具链，不喜欢引用不存在的符号。我们不再列出仅为 Android 构建定义的 `JNI_OnLoad`，而是为 Android 使用单独的版本脚本。

- **ci**: 将 CI 移至 FreeBSD 14.2，从已停产的 14.0 升级。我们的 FreeBSD CI 在过去几周的某个时候坏了，直到导致上一个版本无法发布才被注意到。哎呀！

[@mrmacete]: https://github.com/mrmacete
