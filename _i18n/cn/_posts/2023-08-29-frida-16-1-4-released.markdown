---
layout: news_item
title: 'Frida 16.1.4 发布'
date: 2023-08-29 15:58:08 +0200
author: oleavr
version: 16.1.4
categories: [release]
---

这次有一些令人兴奋的改进：

- ios: 修复 iOS 17 上的 spawn()。感谢 [@hsorbo][]！
- ios: 添加对 rootless 系统的支持。感谢结对编程，[@hsorbo][]！
- android: 修复动态链接器兼容性回归。感谢结对编程，[@hsorbo][]！感谢 [@getorix][] 的报告。
- gumjs: 添加 Worker API，以便可以将繁重的处理移至后台线程，从而允许及时处理 hook。目前仅在 QuickJS 运行时中实现。感谢 [@mrmacete][] 追踪并修复实现中的最后一分钟错误。
- linux: 改进尝试附加到濒临死亡的进程时的错误处理。


[@hsorbo]: https://x.com/hsorbo
[@getorix]: https://x.com/getorix
[@mrmacete]: https://x.com/bezjaje
