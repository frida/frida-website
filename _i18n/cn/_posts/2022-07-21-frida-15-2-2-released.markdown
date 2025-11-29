---
layout: news_item
title: 'Frida 15.2.2 发布'
date: 2022-07-21 20:01:25 +0200
author: oleavr
version: 15.2.2
categories: [release]
---

另外两个改进，正好赶上周末：

- darwin: 始终在本地托管系统会话。通过这种方式，我们避免了将 frida-helper 写入临时文件并生成它只是为了使用系统会话 (PID 0)。
- darwin: 重做 frida-helper IPC 以避免 Mach 端口。这意味着我们避免了在最近版本的 macOS 上崩溃。感谢合著者 [@hsorbo][] 在这方面富有成效的结对编程！


[@hsorbo]: https://twitter.com/hsorbo
