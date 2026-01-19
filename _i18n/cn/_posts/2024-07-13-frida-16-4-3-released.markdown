---
layout: news_item
title: 'Frida 16.4.3 发布'
date: 2024-07-13 00:34:16 +0200
author: oleavr
version: 16.4.3
categories: [release]
---

此版本包含大量改进：

- fruity: 添加对 Windows 和 Linux 上联网设备的支持。
- ncm: 如果需要，切换 USB 设备配置。
- network-stack: 修复 TcpConnection use-after-free。
- fruity: 修复 LWIP.NetworkInterface 绑定。
- fruity: 删除被遗忘的 .pcap 调试输出。
- dtx: 修复 DTXConnection 与 DTXChannel 的拆卸。
- buffer: 向 read_string() 添加内容验证。
- buffer: 向 read_fixed_string() 添加内容验证。
- java: 修复 Android >= 14 上的 Java.choose()。感谢 [@mbricchi][]！
- java: 处理 CMC GC 策略。感谢 [@mbricchi][]！


[@mbricchi]: https://github.com/mbricchi
