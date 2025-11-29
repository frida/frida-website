---
layout: news_item
title: 'Frida 17.2.9 发布'
date: 2025-07-02 12:59:19 +0200
author: oleavr
version: 17.2.9
categories: [release]
---

这次我们为您带来初步的 iOS 26 支持，以及针对我们的 Node.js 绑定的错误修复：

- **fruity**: 添加了对在强制执行调试器映射 (iOS 26) 且我们无法从目标进程内部将内存保护翻转回可执行文件的 iOS 目标上注入 gadget 的支持。在这种情况下，gadget 配置将把 `code_signing` 设置为 `required`，直到 Interceptor 支持强制执行的调试器映射。感谢 [@mrmacete][]！

- **device**: 修复了 `stdio` 选项未通过 `spawn()` 传递的问题，导致子进程始终继承 stdio。由 [@hsorbo][] 共同编写。


[@mrmacete]: https://twitter.com/bezjaje
[@hsorbo]: https://twitter.com/hsorbo
