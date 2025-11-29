---
layout: news_item
title: 'Frida 1.6.4 发布'
date: 2014-10-19 04:04:00 +0100
author: oleavr
version: 1.6.4
categories: [release]
---

是时候发布错误修复版本了！

Stalker 改进：

- 引擎不再为每个被跟踪的线程预分配 256 MB 的固定块，现在以重入安全的方式动态增长。
- 消除了缓存查找逻辑中的一个错误，即某些块总是会导致缓存未命中。因此，这些块每次即将执行时都会重新编译，从而减慢执行速度并用越来越多的条目堵塞缓存，最终耗尽内存。
- 现在可以正确处理 RIP 相对 `cmpxchg` 指令的重定位。

更好的 Dalvik 集成 (Android)：

- 现在可以加载应用程序自己的类。
- 修复了几个编组错误。

脚本运行时：

- 具有相同目标地址的多个 NativeFunction 不再导致 use-after-free。

此外，[CryptoShark 0.1.2](https://github.com/frida/cryptoshark) 已经发布，具有升级的 Frida 引擎和大量性能改进，因此 GUI 能够跟上 Stalker。趁热去拿吧！
