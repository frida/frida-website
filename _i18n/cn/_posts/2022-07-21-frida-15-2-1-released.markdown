---
layout: news_item
title: 'Frida 15.2.1 发布'
date: 2022-07-21 09:36:52 +0200
author: oleavr
version: 15.2.1
categories: [release]
---

这次有两个小而重要的错误修复：

- compiler: 忽略 watch() 期间不相关的更改。
- darwin: 提高内存范围文件信息的准确性。通过在可用时使用 PROC_PIDREGIONPATHINFO2，以便查询受限于 vnode 支持的映射。感谢 [@i0n1c][] 发现并追踪此长期存在的问题。


[@i0n1c]: https://twitter.com/i0n1c
