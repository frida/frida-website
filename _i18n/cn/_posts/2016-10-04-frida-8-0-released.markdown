---
layout: news_item
title: 'Frida 8.0 发布'
date: 2016-10-04 23:00:00 +0200
author: oleavr
version: 8.0
categories: [release]
---

是时候升级到下一个主要版本了。

首先是长期存在的问题，即附加到同一进程的多个 Frida 客户端被迫协调，以便在其他客户端仍在使用会话时，没有一个客户端会调用 *detach()*。

对于大多数 Frida 用户来说，这可能不是什么大问题。但是，如果一个正在运行的 *frida-server* 由多个客户端共享，我们也会遇到同样的问题。您可能在一个终端中运行 *frida-trace*，而在另一个终端中使用 REPL，两者都附加到同一个进程，然后您不会希望其中一个调用 *detach()* 导致另一个被踢出。

你们中的一些人可能已经尝试过这个，并观察到它按预期工作，但这归功于 frida-server 中一些疯狂的逻辑，它会跟踪有多少客户端对同一个进程感兴趣，所以如果其他客户端仍然订阅了同一个会话，它可以忽略 *detach()* 调用。如果某个客户端突然断开连接，它还有一些逻辑来清理该客户端的资源，例如脚本。

从 8.0 开始，我们将感知会话移到了 agent 中，并保持面向客户端的 API 不变，但更改了一个小细节。每次调用 *attach()* 现在都会获得自己的 Session，并且注入的 agent 知道它。这意味着您可以随时调用 *detach()*，并且只有在您的会话中创建的脚本才会被销毁。此外，如果您的会话是最后一个活动的，Frida 将从目标进程中卸载其 agent。

那是此版本的重大变化，但我们并没有止步于此。

Frida 脚本的一个重要特性是您可以与它们交换消息。脚本可以调用 *send(message[, data])* 发送 JSON 可序列化的 *message*，并可选地在旁边发送 *data* 的二进制 blob。后者是为了让您不必花费 CPU 周期将二进制数据转换为包含在 *message* 中的文本。

也可以在另一个方向进行通信，当您从应用程序向其 *post_message()* 时，脚本将调用 *recv(callback)* 以获得 *callback*。这允许您向脚本发布 JSON 可序列化的 *message*，但不支持在旁边发送 *data* 的二进制 blob。

为了解决这个缺点，我们将 *post_message()* 重命名为 *post()*，并给它一个可选的第二个参数，允许您在旁边发送 *data* 的二进制 blob。

我们还通过从纯 C 数组迁移到 [GBytes](https://developer.gnome.org/glib/stable/glib-Byte-Arrays.html#GBytes) 改进了 C API，这意味着我们能够最大限度地减少数据流经我们的 API 时复制数据的次数。

最后，让我们总结一下变化：

8.0.0:

- core: 添加对多个并行会话的支持
- core: 将 Script 的 *post_message()* 重命名为 *post()* 并添加对向脚本传递带外二进制数据的支持
- core: 用 *GBytes* 替换 C 数组以提高性能
- core: 修复 libgee 中 use-after-free 引起的堆损坏
- core: 修复多个崩溃
- core: 修复 macOS Sierra 上的导出枚举崩溃
- core: 添加对在 Valgrind 上运行的基本支持
- core: 将 macOS 要求提升到 10.9，以便我们可以依赖 libc++
- node: 更新到新的 8.x API
- python: 更新到新的 8.x API
- swift: 更新到新的 8.x API
- swift: 升级到 Swift 3
- qml: 更新到新的 8.x API
- clr: 更新到新的 8.x API
- clr: 堵塞泄漏

8.0.1:

- node: 修复 *Script#post()*

8.0.2:

- core: 修复从我们的 JS 线程调用 *recv().wait()* 时的死锁

8.0.3:

- core: 将 Interceptor 基本开销减少高达 65%
- core: 在我们的 V8 运行时中最大限度地减少 Interceptor GC 搅动，使用与我们的 Duktape 运行时相同的回收和写时复制技巧
- core: 加速 macOS 和 iOS 上的 *gum_process_get_current_thread_id()*

享受吧！
