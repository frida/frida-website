---
layout: news_item
title: 'Frida 1.0.6 发布'
date: 2014-01-11 23:00:00 +0100
author: oleavr
version: 1.0.6
categories: [release]
---

此版本简化了许可并修复了自 HN 发布以来社区报告的错误。

主要是：
- 将剩余的 GPLv3+ Frida 组件重新许可为 LGPLv2.1+（与 frida-gum 相同）。
- Tracer 在 64 位上工作，函数地址在上层范围内
- Linux 构建链接 Frida 自己的库，而不是构建机器的相应库。
