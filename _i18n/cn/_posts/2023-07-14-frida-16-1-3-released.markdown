---
layout: news_item
title: 'Frida 16.1.3 发布'
date: 2023-07-14 13:18:10 +0200
author: oleavr
version: 16.1.3
categories: [release]
---

是时候发布新版本了，正好赶上周末：

- server: 添加 iOS >= 17 缺失的 entitlement。感谢 [@alexhude][] 帮助弄清这个问题。
- stalker: 改进 arm 和 arm64 上的独占存储处理。我们不再可能扩展当前块以包含超出块自然结束位置的指令，而是采用更安全的方法：一旦遇到独占存储，我们就回顾以前生成的块，看看是否能找到一个带有独占加载的块。如果找到，我们将此块范围标记为使用独占访问。我们还会使块无效，以便在重新编译时省略有问题的检测。为了也允许自定义 transformer 调整其生成的代码，我们引入了 StalkerIterator.get_memory_access()。感谢有趣且富有成效的结对编程，[@hsorbo][]！
- gumjs: 添加 *StalkerIterator.memoryAccess*，允许自定义 transformer 确定添加什么样的检测是安全的，而不会干扰独占存储操作。设置为 'open'（当诸如 callout 之类的“嘈杂”检测是安全的时）或 'exclusive'（当此类检测有风险并可能导致无限循环时）。（由于独占存储失败，随后的每次重试也会失败。）
- gumjs: 修复 arm 上 Stalker 的 CModule 绑定。
- stalker: 修复添加的 slab 中失效时的崩溃。
- arm64-writer: 添加 put_eor_reg_reg_reg()。感谢有趣且富有成效的结对编程，[@hsorbo][]！


[@alexhude]: https://github.com/alexhude
[@hsorbo]: https://twitter.com/hsorbo
