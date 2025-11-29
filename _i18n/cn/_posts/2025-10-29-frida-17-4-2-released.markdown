---
layout: news_item
title: 'Frida 17.4.2 发布'
date: 2025-10-29 16:48:10 +0100
author: oleavr
version: 17.4.2
categories: [release]
---

本周是 Simmy 后端改进的一批更新。感谢 [@hsorbo][] 的结对编程，带来了以下改进：

- simmy: 实现 `get_frontmost_application()`，使得弄清楚当前谁在聚光灯下变得轻而易举。
- simmy: 修复 `query_system_parameters()` 中报告的 `hardware.product`，例如返回 `iPhone18,2` 而不是 “iPhone 17 Pro Max”。
- simmy: 连接应用程序图标。

享受吧！


[@hsorbo]: https://x.com/hsorbo
