---
layout: news_item
title: 'Frida 16.4.8 发布'
date: 2024-08-02 14:05:27 +0200
author: oleavr
version: 16.4.8
categories: [release]
---

快速的错误修复版本，旨在进一步改进我们的 Fruity 后端：

- lockdown-client: 冒泡 CONNECTION_CLOSED 错误。感谢 [@hsorbo][]！
- fruity: 使 find_usbmux_device() 不抛出异常。感谢 [@hsorbo][]！
- fruity: 防止 lockdown open -> close 循环。
- fruity: 修复已关闭 lockdown 客户端的失效。感谢 [@hsorbo][]！


[@hsorbo]: https://twitter.com/hsorbo
