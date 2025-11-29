---
layout: news_item
title: 'Frida 17.4.3 发布'
date: 2025-10-31 20:24:19 +0100
author: oleavr
version: 17.4.3
categories: [release]
---

万圣节带来了一小批修复和改进：

- simmy: 当启用系统完整性保护 (SIP) 时，优雅地降级依赖于注入 SpringBoard 的功能。这意味着 `get_frontmost_application()` 和图标检索现在会回退而不是崩溃。

- simmy: 修复了当请求 bundle ID 子集时已安装应用的枚举问题。感谢 [@hsorbo][] 的协助！

- docs: 更新 README 的 Apple 证书部分以反映当前的现实。感谢 [@gemesa][] 发现并修复了过时的部分！

享受吧，祝黑客愉快！


[@hsorbo]: https://x.com/hsorbo
[@gemesa]: https://github.com/gemesa
