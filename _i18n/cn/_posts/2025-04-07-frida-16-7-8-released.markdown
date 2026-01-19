---
layout: news_item
title: 'Frida 16.7.8 发布'
date: 2025-04-07 10:09:08 +0200
author: oleavr
version: 16.7.8
categories: [release]
---

快速的错误修复版本，用于修复 Apple 操作系统上的崩溃。

感谢 [@mrmacete][] 贡献了以下修复：

- darwin: 修复 find_module_by_address 中的模块类型。
  这是一个导致微妙崩溃的类型混淆。

[@mrmacete]: https://twitter.com/bezjaje
