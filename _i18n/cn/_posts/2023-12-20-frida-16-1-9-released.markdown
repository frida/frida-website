---
layout: news_item
title: 'Frida 16.1.9 发布'
date: 2023-12-20 00:40:51 +0100
author: oleavr
version: 16.1.9
categories: [release]
---

此版本中有相当多的好东西：

- interceptor: 也暂停隐藏的线程。这可以防止在使用 Interceptor hook 与内部可能使用的任何函数位于同一页面上的函数时，我们自己的线程发生随机 SIGBUS 崩溃。感谢 [@mrmacete][]！
- darwin: 迁移到我们的 POSIX Exceptor 后端。Mach 异常处理 API 在最近的 Apple OS 版本中变得越来越受限。
- darwin: 解析 arm64 上的导入蹦床，允许我们 hook 诸如 sigaction() 之类的目标。
- linux: 改进 spawn() 以处理再次命中 r_brk 的情况。
- linker: 改进 spawn() 以考虑 RTLD 符号的磁盘 ELF。这意味着我们可能会在其他 Android 系统上找到 r_debug。
- linux: 修复 DT_INIT_ARRAY 包含哨兵值时的 spawn()。
- linux: 改进 spawn() 以使用 DT_PREINIT_ARRAY（如果存在）。
- android: 处理 RTLD 回退逻辑中的符号链接。


[@mrmacete]: https://x.com/bezjaje
