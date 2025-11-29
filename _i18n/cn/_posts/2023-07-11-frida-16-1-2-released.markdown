---
layout: news_item
title: 'Frida 16.1.2 发布'
date: 2023-07-11 17:44:02 +0200
author: oleavr
version: 16.1.2
categories: [release]
---

是时候发布新版本来改进一些事情了：

- darwin: 修复 Stalker.follow() 回归，其中正在进行的系统调用会被残酷地中断，通常导致目标崩溃。感谢结对编程，[@hsorbo][]！
- gumjs: 为 QuickJS 实现 WeakRef API。
- compiler: 将 @types/frida-gum 升级到 18.4.0。


[@hsorbo]: https://twitter.com/hsorbo
