---
layout: news_item
title: 'Frida 16.4.0 发布'
date: 2024-07-05 15:32:58 +0200
author: oleavr
version: 16.4.0
categories: [release]
---

此版本包含一些令人兴奋的新事物。让我们直接潜入。

## CoreDevice

正如 16.3.0 发行说明中提到的，[@hsorbo][] 和我正在致力于为 Linux 内核的 CDC-NCM 驱动程序提交补丁，以使其与 Apple 的专用网络接口兼容。这已经进入 [upstream][]，并将成为 Linux 6.11 的一部分。

与此同时，对于那些在 Windows 上使用 Frida 的人，我们刚刚实现了一个 [minimal user-mode driver][]，当 Frida 检测到内核没有提供驱动程序时，它现在会使用该驱动程序。我们利用 [lwIP][] 完全在用户空间中执行以太网和 IPv6。结果是 Frida 可以在 libusb 支持的任何平台上支持 CoreDevice。

## EOF

还有很多其他令人兴奋的更改，所以一定要查看下面的变更日志。

享受吧！

### 变更日志

- fruity: 重做以支持用户空间 CDC-NCM。
- fruity: 添加对 iOS >= 18 上 dyld 重启的支持。
- fruity: 在 iOS >= 18 上等待 ObjC 运行时初始化。
- fruity: 修复没有 usbmux 连接可用时的 gadget 上传。
- fruity: 改进 open_channel() 以支持 tcp:service-name。
- fruity: 失败时重试 RSD 端口查找。
- fruity: 恢复 HostChannelProvider 实现。
- fruity: 如果 libSystem 已初始化，则跳过获取 dyld 符号。
- fruity: 连接 MacOSCoreDeviceTransport 事件处理。
- fruity: 修复 macOS CoreDevice 连接类型逻辑。
- fruity: 将 `os.build` 和 `hardware` 添加到公开的系统参数。感谢 [@as0ler][]！
- server 和 gadget: 在 iOS 和 tvOS 上侦听 Apple 的 CoreDevice 隧道网络接口。
- xpc-service: 修复带数组的 request() 处理。感谢 [@hsorbo][]！
- xpc-service: 支持类型注释请求参数。
- python: 支持将元组解组为 GVariant。
- python: 修复将 bool 解组为 GVariant。
- node: 支持在编组为 GVariant 时进行类型注释。
- node: 将 Node.js 要求提高到 `>=16 || 14 >=14.17`，以匹配 minimatch。
- java: 修复 Android 上的 registerClass() 字段项排序。感谢 [@eybisi][]！


[@hsorbo]: https://twitter.com/hsorbo
[upstream]: https://github.com/torvalds/linux/commit/3ec8d7572a69d142d49f52b28ce8d84e5fef9131
[minimal user-mode driver]: https://github.com/frida/frida-core/blob/31188db39a7c9ae24f640a34b3fdf701f4a93bb3/src/fruity/ncm.vala
[lwIP]: https://savannah.nongnu.org/projects/lwip/
[@as0ler]: https://twitter.com/as0ler
[@eybisi]: https://github.com/eybisi
