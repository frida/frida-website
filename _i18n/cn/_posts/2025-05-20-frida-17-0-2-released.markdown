---
layout: news_item
title: 'Frida 17.0.2 发布'
date: 2025-05-20 22:41:03 +0200
author: oleavr
version: 17.0.2
categories: [release]
---

此版本带来了一些错误修复：

- **Compiler**: 将 frida-compile 和 frida-fs 更新到最新版本。
- **gum**: 修复了与 GObject 相关的被遗忘的精简位，现在它又变回了必需的库。
- **gumjs**: 修复了在没有断言的情况下构建时的已分配但未使用的警告。
