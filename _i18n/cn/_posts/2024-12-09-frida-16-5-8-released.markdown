---
layout: news_item
title: 'Frida 16.5.8 发布'
date: 2024-12-09 00:32:29 +0100
author: oleavr
version: 16.5.8
categories: [release]
---

令人兴奋的新版本，包含了各个组件的性能增强和错误修复，特别是在我们的 Fruity 后端。[@hsorbo][] 和我合作为您带来了以下改进：

- **fruity:** 通过多重传输提升 NCM 性能，提高数据传输效率。
- **fruity:** 改进用户空间 NCM 驱动程序以执行批处理，减少突发情况下的数据包丢失。
- **fruity:** 启用 lwIP TCP 时间戳和 SACK 以与 Linux IP 堆栈默认值保持一致，增强网络性能。
- **fruity:** 将 lwIP TCP 最大段大小 (MSS) 提高到 4036，以获得更好的 TCP 隧道性能。
- **fruity:** 考虑 `frida-server` `bind()` 延迟以提高连接建立的可靠性。
- **fruity:** 修复拆卸期间 USB 操作创建时的崩溃。
- **fruity:** 通过在内核 NCM 可用时避免不必要的 USB 访问，改进非 macOS 系统上的 USB 设备处理。
- **fruity:** 通过确保即使运行冲突的服务也能正确建立连接，修复直接通道的可靠性。感谢 [@mrmacete][] 帮助追踪此问题。
- **fruity:** 改进 `TcpTunnelConnection` 拆卸，以确保在远程端关闭连接时进行适当的清理。

- **api:** 生成适当的 GObject Introspection Repository (GIR)，包括必要的类型并省略内部类型。
- **api:** 避免在 API 中公开内部类型。
- **api:** 省略涉及 `HostSession` 的 API。

- **build:** 修改输出逻辑以避免对输出文件的冗余写入，从而加快增量构建速度。
- **build:** 利用 Meson 对多个输出的 `custom_target()` 支持，避免多次解析 API。
- **compat:** 创建相对子项目符号链接，以便可以在不破坏构建的情况下移动源代码树。
- **compat:** 修复子项目 `compat.symlink_to()` 中的错误处理。

- **windows:** 修复不存在 PID 的 `cpu_type_from_pid()`。
- **windows:** 在 Windows 11+ 上使用 `GetProcessInformation()` 以确保证确使用 `ProcessMachineTypeInfo`。

一如既往，非常感谢 [@hsorbo][] 和 [@mrmacete][] 为使此版本成为可能而做出的宝贵贡献。

[@hsorbo]: https://twitter.com/hsorbo
[@mrmacete]: https://twitter.com/mrmacete
