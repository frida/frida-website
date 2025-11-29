---
layout: news_item
title: 'Frida 16.4.5 发布'
date: 2024-07-17 22:43:23 +0200
author: oleavr
version: 16.4.5
categories: [release]
---

快速的错误修复版本，旨在解决几个问题：

- xpc-client: 在 request() 中连接 cancellable，以支持在我们的 Fruity macOS CoreDevice 后端取消 remotepairingd 请求。
- java: 正确处理 Android ART CMC GC 策略。感谢 [@mbricchi][]！
- java: 修复较新 ART APEX 上的 Java.choose()。感谢 [@mbricchi][]！


[@mbricchi]: https://github.com/mbricchi
