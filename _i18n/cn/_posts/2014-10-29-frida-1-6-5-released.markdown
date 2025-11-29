---
layout: news_item
title: 'Frida 1.6.5 发布'
date: 2014-10-29 23:00:00 +0100
author: oleavr
version: 1.6.5
categories: [release]
---

现在是发布时间，也是修复一些错误的时间：

- 现在支持 iOS 8.1，ARM64 支持比以往任何时候都好。
- iOS USB 传输在向设备发送突发数据时不再断开连接。这通常会在使用 `frida-trace` 并跟踪一堆函数时发生，导致通过线路发送突发数据。这实际上是 [影响 Mac 和 iOS 的通用网络问题](https://bugzilla.gnome.org/show_bug.cgi?id=11059)，但在使用 Frida 与系留 iOS 设备一起使用时非常容易重现。
- 消除了 Python 解释器关闭时的崩溃。
- `frida-trace` 脚本中的 `onEnter` 和 `onLeave` 回调现在在调用时将 `this` 绑定到正确的对象，这意味着它绑定到特定于该线程和调用的对象，而不是由所有线程和调用共享的对象。
