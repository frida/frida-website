---
layout: news_item
title: 'Frida 16.4.4 发布'
date: 2024-07-16 15:25:08 +0200
author: oleavr
version: 16.4.4
categories: [release]
---

此版本包含大量改进：

- darwin: 处理 macOS Sequoia 和 iOS 18 上的 dyld 重启。
- darwin: 在 macOS Sequoia 和 iOS 18 上等待 ObjC 初始化，如果有的话利用 notifyObjCInit()。
- fruity: 改进 CoreDevice 配对支持：
  - 修复对多重配对关系的支持。
  - 保持内存中的对等体存储最新，因此新的配对关系不需要重启进程就能与网络上的配对服务匹配。
- ncm: 在更改配置之前分离所有驱动程序。
- ncm: 避免使用损坏的内核 NCM 驱动程序。
- darwin: 修复模拟器上的 sysroot。感谢 [@CodeColorist][]！
- darwin-mapper: 本地解析共享缓存符号，尽可能避免解析器函数，从而避开我们现有的生成构造函数尝试将结果写入只读页面的问题。
- gumjs: 修复应用程序线程上 recv().wait() 中的竞争。感谢 [@HexKitchen][]！
- python: 消除不稳定的引用计数 API 的使用，以便使用较新 Python 头文件构建的扩展仍然可以在较旧的 Python 运行时上工作。


[@CodeColorist]: https://twitter.com/CodeColorist
[@HexKitchen]: https://github.com/HexKitchen
