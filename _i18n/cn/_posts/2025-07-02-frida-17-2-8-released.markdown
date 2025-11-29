---
layout: news_item
title: 'Frida 17.2.8 发布'
date: 2025-07-02 00:09:26 +0200
author: oleavr
version: 17.2.8
categories: [release]
---

快速的错误修复版本，解决影响我们 Windows 用户的问题：

- **package-manager**: 修复 Windows 上损坏的 `#if`。不正确的预处理器指令导致在 Windows 平台上编译时构建失败。
