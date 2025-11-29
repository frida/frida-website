---
layout: news_item
title: 'Frida 16.0.9 发布'
date: 2023-02-11 10:35:06 +0100
author: oleavr
version: 16.0.9
categories: [release]
---

此版本的主题是改进对越狱 iOS 的支持。我们现在支持 iOS 16.3，包括应用程序列表和启动。还包括改进的 iOS 15 支持，以及针对旧 iOS 版本的一些回归修复。

此版本中还有一些其他好东西，所以一定要查看下面的变更日志。

享受吧！

### 变更日志

- darwin: 修复 iOS >= 16 上的应用程序列表和启动。感谢与 [@hsorbo][] 进行富有成效的结对编程！
- darwin: 修复现代 dyld 早期插桩期间的崩溃。
- darwin: 修复早期插桩中的断点冲突，这是 16.0.8 中作为改进 spawn() 性能的一部分引入的回归。感谢 [@mrmacete][]！
- package-server-ios: 强制 xz 压缩。
- darwin-grafter: 如果需要，创建多个段。感谢 [@mrmacete][]！
- interceptor: 在 Darwin grafted 导入激活时翻转页面保护。感谢 [@mrmacete][]！
- stalker: 修复没有回写的 ARM LDMIA 的处理。
- darwin: 添加 query_protection()。感谢 [@mrmacete][]！
- darwin: 避免在强化进程中探测内核任务端口。感谢 [@as0ler][]！
- darwin: 修复 Process.modify_thread() 的可靠性。
- darwin: 修复启用了 tweak 的 iOS 上的 query_hardened()。感谢 [@as0ler][]！
- darwin: 使 Process.modify_thread() 破坏性更小。
- darwin: 优化 Process.modify_thread()。
- darwin: 添加 modify_thread()。
- arm-writer: 添加 put_ldmia_reg_mask_wb()。
- gumjs: 修复运行时序列化不处理 unicode 的问题。感谢 [@milahu][]！
- python: 向 RPC 调用添加异步变体。感谢 [@yotamN][]！
- python: 为 core 添加特定的信号类型提示。感谢 [@yotamN][]！


[@hsorbo]: https://twitter.com/hsorbo
[@mrmacete]: https://twitter.com/bezjaje
[@as0ler]: https://twitter.com/as0ler
[@milahu]: https://github.com/milahu
[@yotamN]: https://github.com/yotamN
