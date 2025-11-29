---
layout: news_item
title: 'Frida 16.0.4 发布'
date: 2022-11-26 01:35:58 +0100
author: oleavr
version: 16.0.4
categories: [release]
---

这是一个全新的版本，正好赶上周末！🎉 这次有几个关键的稳定性修复。

享受吧！

### 变更日志

- gumjs: 修复 V8 JobState 逻辑中的 use-after-free。感谢 [@pancake][] 报告并帮助追踪此问题！
- android: 修复竞争性的 Zygote 和 system_server 检测。感谢与 [@hsorbo][] 进行有趣且富有成效的结对编程！
- submodules: 添加 frida-go。感谢 [@lateralusd][]！


[@pancake]: https://twitter.com/trufae
[@hsorbo]: https://twitter.com/hsorbo
[@lateralusd]: https://github.com/lateralusd
