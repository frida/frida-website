---
layout: news_item
title: 'Frida 17.4.4 发布'
date: 2025-11-01 00:38:24 +0100
author: oleavr
version: 17.4.4
categories: [release]
---

针对 Darwin 用户的小而重要的更新：

- **darwin**: 恢复在 rootful 系统上运行 iOS ≥ 16 时的应用列表/启动功能。这使得 frida-core 提交 dccb612 起死回生，此前 8108d4d 在修复两个 Interceptor 单例泄漏时破坏了它。事实证明，springboard.m 中的泄漏是有意的，作为一次性初始化逻辑，不需要拆卸；没有它，我们应用的插桩会立即被还原。感谢 [@alexhude][] 的提醒。


[@alexhude]: https://github.com/alexhude
