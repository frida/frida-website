---
layout: news_item
title: 'Frida 17.0.6 发布'
date: 2025-05-28 23:17:13 +0200
author: oleavr
version: 17.0.6
categories: [release]
---

快速的错误修复版本，包含 [@londek][] 的重要贡献。在此版本中，我们解决了以下问题：

- **darwin**: 修复了 launchd 代理，它仍在使用已删除的旧 GumJS API。这阻止了代理在越狱的 iOS/iPadOS/tvOS 系统上运行。

[@londek]: https://github.com/londek
