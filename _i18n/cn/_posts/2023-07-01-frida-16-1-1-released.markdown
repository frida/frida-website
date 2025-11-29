---
layout: news_item
title: 'Frida 16.1.1 发布'
date: 2023-07-01 06:42:06 +0200
author: oleavr
version: 16.1.1
categories: [release]
---

这次只有几个变化：

- compiler: 将 frida-compile 升级到 16.3.0，现在包含 TypeScript 5.1.5 和其他改进。其中包括 [@hsorbo][] 的修复，该修复将默认 *moduleResolution* 更改为 *Node16*。
- stalker: 添加 Iterator.get_capstone()，以便 transformer 可以使用需要 Capstone 句柄的 Capstone API。
- node: 修复 RPC 消息数组检查。感谢 [@ZachQin][]！


[@hsorbo]: https://twitter.com/hsorbo
[@ZachQin]: https://github.com/ZachQin
