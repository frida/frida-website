---
layout: news_item
title: 'Frida 16.7.9 发布'
date: 2025-04-07 19:32:56 +0200
author: oleavr
version: 16.7.9
categories: [release]
---

事实证明软件很难！在我们上一个版本发布的同一天，我们推出了另一个快速的错误修复版本来解决出现的一些问题。非常感谢 [@mrmacete][] 的贡献。以下是新内容：

- **channel**: 在空缓冲区上中断读取循环。（感谢 [@mrmacete][]！）
- **device-manager**: 修复拆卸逻辑，在 `HostSessionService` 尚未 `start()` 的情况下，我们也将会 `stop()` 它。

[@mrmacete]: https://twitter.com/bezjaje
