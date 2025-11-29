---
layout: news_item
title: 'Frida 16.4.6 发布'
date: 2024-07-22 21:47:49 +0200
author: oleavr
version: 16.4.6
categories: [release]
---

此版本包含大量改进：

- fruity: 如果存在，使用来自 USB 传输的 UsbmuxDevice，以便我们可以访问环回接口，并获得更好的性能。
- fruity: 处理非 macOS 上不支持隧道的设备。
- fruity: 如果存在，从 USB 传输公开名称。如果是 UsbmuxTransport，它具有更具描述性的名称。
- gumjs: 确保在构建 devkit 之前构建 Gum .a。感谢 [@Hexploitable][]！
- gumjs: 生成更简单的枚举值查找代码。
- spinlock: 合并为单个实现。
- java: 修复 Android >= 15 的 art::Thread::DecodeJObject。感谢 [@esauvisky][]！


[@Hexploitable]: https://twitter.com/Hexploitable
[@esauvisky]: https://github.com/esauvisky
