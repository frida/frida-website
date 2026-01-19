---
layout: news_item
title: 'Frida 16.1.8 发布'
date: 2023-11-28 22:06:07 +0100
author: oleavr
version: 16.1.8
categories: [release]
---

这次有三个令人兴奋的变化：

- process: 添加 *get_main_module()*，作为 *Process.mainModule* 暴露给 JavaScript。当需要知道哪个模块代表进程的主可执行文件时很有用。过去，这通常是通过枚举加载的模块并假设列表中的第一个就是它来实现的。在最新的 Apple 操作系统上情况不再如此，因此我们通过这个新 API 提供了一个高效且可移植的解决方案。感谢 [@mrmacete][]！
- compiler: 将 @types/frida-gum 升级到 18.5.0，现在包含最近 API 添加的类型定义。
- barebone: 修复与最新 Corellium 的兼容性。


[@mrmacete]: https://x.com/bezjaje
