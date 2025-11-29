---
layout: news_item
title: 'Frida 17.4.0 发布'
date: 2025-10-12 08:35:50 +0200
author: oleavr
version: 17.4.0
categories: [release]
---

又到了功能丰富的发布时间！亮点：

- simmy: 全新的后端，通过 CoreSimulator.framework 与 Apple 模拟器对话。Spawn 应用、插桩进程，通常像对待任何其他设备一样对待模拟器 —— 所有这些都可以在 Frida 中舒适地完成。

- darwin: 支持 `dyld_sim` 的早期插桩，因此您甚至可以在动态加载程序完成模拟进程的引导之前附加并加载脚本。

- darwin: 修复最新 iOS 18 模拟器上的 sysroot 检测，其中 `dyld_sim` 现在对 `_dyld_image_count` 和 `TASK_DYLD_ALL_IMAGE_INFO_64` 隐藏。感谢 [@CodeColorist][] 追踪到这个问题！

- fruity: 每当我们遇到 `InvalidHostID` 错误时自动取消配对，允许下一次配对尝试成功。[@mrmacete][] 的出色工作！

- android: 将 `system-server` 更新为 `frida-java-bridge` 7.0.9。更改：
  - 修复 Android 16 上的 Java.deoptimize\*() 和 Java.backtrace()。感谢 [@hsorbo][]！
  - 改进类型定义。感谢 [@yotamN][]！

- host-session: 添加跨后端通信，因此通过一个后端发现的设备现在可用于另一个后端的内部。

- base: 引入 `StdioPipes` 和 `FileDescriptor` 助手，由 Darwin、Linux 和 FreeBSD 后端共享。

- value: 新的 `VariantReader.list_members()` 助手，便于内省。

享受吧！


[@CodeColorist]: https://x.com/CodeColorist
[@mrmacete]: https://x.com/bezjaje
[@hsorbo]: https://x.com/hsorbo
[@yotamN]: https://github.com/yotamN
