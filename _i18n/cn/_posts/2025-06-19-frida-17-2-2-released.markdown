---
layout: news_item
title: 'Frida 17.2.2 发布'
date: 2025-06-19 23:25:55 +0200
author: oleavr
version: 17.2.2
categories: [release]
---

我们带着快速的错误修复版本回来了：

- package-manager: 修复了 lockfile 最新路径。
- package-manager: 仅报告已安装的包。不再包含未触及的顶级包。还简化了 `install()` 逻辑。
