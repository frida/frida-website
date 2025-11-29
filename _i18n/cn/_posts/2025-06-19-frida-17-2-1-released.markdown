---
layout: news_item
title: 'Frida 17.2.1 发布'
date: 2025-06-19 21:03:53 +0200
author: oleavr
version: 17.2.1
categories: [release]
---

另一个快速的错误修复版本，解决了自上次发布以来发现的几个问题：

- compiler: 在 Android 上，将后端设为共享库，以避免由于线程局部存储导致的动态链接问题。
- python: 公开 `PackageManager.registry` 属性。
- python: 修复了 `Compiler`、`PackageManager` 和 `FileMonitor` 缺少的顶级计数器逻辑，确保信号发射正常工作。
- python: 为 `PackageManager` 类型添加了 `__repr__` 方法，以便更好地调试。
- core: 修复了当 libsoup 用作子项目时的构建问题。
