---
layout: news_item
title: 'Frida 16.5.9 发布'
date: 2024-12-09 00:52:39 +0100
author: oleavr
version: 16.5.9
categories: [release]
---

哎呀，软件很难！这是另一个快速发布，旨在解决我们今天早些时候遗漏的一个问题。

我们修复了 Meson 构建脚本中的一个问题，即在 frida-core 的最新更改之后，modulemap 依赖项未正确指定。具体来说，`core_public_h` 现在是一个自定义目标索引，因此我们不能再直接使用它了。相反，我们现在依赖于它的父级 `core_api`。

特别感谢 [@hsorbo][] 共同编写此修复程序。

[@hsorbo]: https://twitter.com/hsorbo
