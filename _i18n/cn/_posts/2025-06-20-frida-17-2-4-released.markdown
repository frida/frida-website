---
layout: news_item
title: 'Frida 17.2.4 发布'
date: 2025-06-20 15:45:42 +0200
author: oleavr
version: 17.2.4
categories: [release]
---

另一个快速的错误修复版本，旨在改进我们的包管理器，[@hsorbo][] 和我一直在努力工作。以下是新内容：

- package-manager: 修复依赖安装死锁。当一个包的子依赖也是安装堆栈中更高层另一个包的依赖时，可能会发生死锁。子依赖会等待更高层的包被物理安装，但那个包在解决其子依赖之前不会完成自己的安装，从而造成循环等待。
- package-manager: 改进清单处理，使我们更接近 npm 的行为。(与 [@hsorbo][] 共同编写。)
- package-manager: 改进进度报告。

[@hsorbo]: https://twitter.com/hsorbo
