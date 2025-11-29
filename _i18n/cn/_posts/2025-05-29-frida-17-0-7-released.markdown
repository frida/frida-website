---
layout: news_item
title: 'Frida 17.0.7 发布'
date: 2025-05-29 17:32:19 +0200
author: oleavr
version: 17.0.7
categories: [release]
---

此版本包含一些重要的修复：

- **device**: 允许代理会话在释放前分离，以应对无序分离可能导致释放时无限挂起的情况。感谢 [@mrmacete][]！
- **darwin**: 处置模块解析器索引，以避免在使用短寿命解析器（例如，在不同任务上）的情况下泄漏本机模块。感谢 [@mrmacete][]！
- **stalker**: 处理没有内联缓存条目的块。

[@mrmacete]: https://twitter.com/bezjaje
