---
layout: news_item
title: 'Frida 16.6.3 发布'
date: 2025-01-14 19:35:41 +0100
author: oleavr
version: 16.6.3
categories: [release]
---

此版本的主要变化是恢复了我们的 Windows 注入器，它被最近的 Gum.Module 重构破坏了。除此之外，我们还提高了跨平台低级 GLib 原语的性能，特别是在我们实现静态分配清理的补丁中。这是必要的，因为 Frida 注入的有效载荷的寿命可能比它注入的进程更短。

享受吧！
