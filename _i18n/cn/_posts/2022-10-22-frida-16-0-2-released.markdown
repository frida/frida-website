---
layout: news_item
title: 'Frida 16.0.2 发布'
date: 2022-10-22 01:59:41 +0200
author: oleavr
version: 16.0.2
categories: [release]
---

今天是星期五！这是一个全新的版本，有很多改进：

- macOS: 修复在 macOS >= 12 上附加到 arm64e 系统应用程序和服务的支持。
- i/macOS: 升级对链式修复的支持。
- iOS: 修复运行 iOS < 14 的 arm64e 设备上的系统会话。
- system-session: 禁用 Exceptor 和监视器。
  - Exceptor 会干扰宿主进程的信号处理，这是有风险的并且容易发生冲突。
  - 监视器对系统会话并不真正有用。
- interceptor: 修复 iOS/arm64 上 grafted 模式下使用的蹦床。感谢 [@mrmacete][]！
- compiler: 修复多个平台上的稳定性问题。
- compiler: 修复 @frida/path shim。
- compiler: 通过在非 x86/64 Linux 上也使用快照来加速事情。
- devkit: 修复 Windows, macOS 和 Linux devkits 中的回归。
- v8: 修复由于我们的 libc-shim 未能实现 V8 依赖的 malloc_usable_size() API 而导致的堆损坏。
- v8: 修复对使用不同快照的脚本的支持，这由于 V8 以前被配置为跨隔离共享只读空间而被破坏。该选项与多个快照冲突。
- v8: 改进拆卸。
- v8: 修复 v8::External API 契约违规。
- v8: 升级到 10.9.42。
- zlib: 升级到 1.2.13。
- gum: 修复基于 ELF 的 OS 的子项目构建。
- python: 修复已发布的 Linux wheels 的标签。
  - 添加旧版平台标签，以便旧版本的 pip 能够识别它们。
  - 假装一些 wheels 需要 glibc >= 2.17，因为较低版本在某些架构上无法识别。


[@mrmacete]: https://twitter.com/bezjaje
