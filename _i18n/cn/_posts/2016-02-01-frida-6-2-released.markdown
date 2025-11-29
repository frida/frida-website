---
layout: news_item
title: 'Frida 6.2 发布'
date: 2016-02-01 22:00:00 +0100
author: oleavr
version: 6.2
categories: [release]
---

现在是发布时间，这次我们为您带来了所有平台上的巨大性能改进、用于查找函数的全新 API 以及 iOS 9 上的重大稳定性改进。

让我们先谈谈后一个主题。你们中的一些人可能已经注意到在 iOS 9 上使用 Frida 时会出现奇怪的错误和死锁。根本原因很简单，我们的内联 hook 导致进程丢失其 [代码签名状态](https://github.com/frida/frida-gum/blob/ae22e0fa94970a9df140757e4aa0467e9deea9aa/tests/core/interceptor.c#L1111) 的 *CS_VALID* 位。这在 iOS 8 和更旧版本上不是问题，因为越狱总是能够修补内核以放宽其代码签名要求。从这个版本开始，我们实施了一些技巧，以便能够在不破坏代码签名状态的情况下进行内联 hook。对于技术好奇的人来说，这意味着我们动态生成一个 .dylib 作为临时文件，写出我们想要修改的内存页面的新版本，例如包含 *open()* 的 libc 内存页面，然后伪签名此二进制文件，要求内核 [F_ADDFILESIGS](https://github.com/frida/frida-gum/blob/ae22e0fa94970a9df140757e4aa0467e9deea9aa/gum/backend-darwin/gumcodesegment-darwin.c#L211) 给它，最后从这个文件 *mmap()* 到原始内存页面之上。

这将我们带到下一个主题：性能。我刚才谈到的技巧实际上确实增加了一些额外的开销，只是为了 hook 一个函数。这也是一种与我们在支持读写执行内存页面和宽松代码签名要求的系统上所能做的截然不同的方法，所以这显然意味着需要重大的架构更改。我也一直在考虑能够一次应用一整批 hook，使我们能够更有效率，并对 hook 何时激活有更多控制。

从这个版本开始，我们的 Interceptor API 现在支持 [事务](https://github.com/frida/frida-gum/blob/ae22e0fa94970a9df140757e4aa0467e9deea9aa/gum/guminterceptor.h#L78-L79)。只需调用 *begin_transaction()*，hook 所有函数，并通过调用 *end_transaction()* 一次性使它们全部处于活动状态。这导致了巨大的性能提升，并且您无需更改现有代码即可免费获得所有这些。这是因为我们在进入 JavaScript 运行时时隐式开始事务，并在离开时结束它（就在我们 *send()* 消息或从 RPC 方法返回之前）。因此，除非您从计时器或像 *Memory.scan()* 这样的异步 API 附加您的 hook，否则它们都将被分批处理到单个事务中并获得性能提升。

以下是我们在性能方面与 CydiaSubstrate 的对比：

{% gist bfd9b65865e9f17914f2 %}

请注意，如果您从 C 或 C++ 使用我们的插桩引擎，您将必须自己调用 *begin_transaction()* 和 *end_transaction()* 才能获得此提升，但即使您不这样做，您的代码仍然可以工作，因为每个操作都将隐式包含一个事务，并且 API 允许嵌套这些调用。

那是函数 hook 性能，但我们并没有止步于此。如果您曾经使用 *frida-trace* 跟踪 Objective-C API，或跨所有加载的库 glob 函数，您可能已经注意到解析所有函数可能需要相当长的时间。如果您将其与早期插桩相结合，它甚至可能花费太长时间以至于我们超过了系统的 [启动超时](https://github.com/frida/frida/issues/103)。所有这些现在都已优化，为了让您了解加速情况，以前需要几秒钟的典型 Objective-C 案例现在只需几毫秒即可完成。

现在是新闻的最后一部分。考虑到动态发现要 hook 的函数是如此常见的用例，而不仅仅是 *frida-trace* 所做的，我们现在有一个 [全新的 API](https://frida.re/docs/javascript-api/#apiresolver) 专门用于此：

![ApiResolver #1](/img/api-resolver-module.png "ApiResolver")

![ApiResolver #2](/img/api-resolver-objc.png "ApiResolver")

最后，这是更改的摘要：

6.2.0:

- core: 改进 Interceptor 以避免破坏 iOS 9 上的动态代码签名
- core: 迁移到基于事务的 Interceptor API 以提高性能
- core: 修复计划回调被延迟释放时的崩溃 (V8 和 Duktape)
- frida-trace: 通过删除 *setTimeout()* 逻辑提高性能，允许在同一事务中应用许多 hook
- frida-trace: 以 50 毫秒的块批量处理日志事件以提高性能

6.2.1:

- core: 添加 *ApiResolver* API
- frida-trace: 通过使用新的 *ApiResolver* API 提高性能

6.2.2:

- core: 修复阻止注入 Windows Store/Universal 应用程序的错误
- core: 修复 32 位 ARM 上拆卸时的崩溃
- core: 添加 frida-inject，这是一种将 agent 注入正在运行的进程的工具，具有与 frida-gadget 类似的语义
- core: (Linux) 防止 libdl 卸载以解决 TLS 析构函数错误
- core: (Linux) 修复快速取消注入时的竞争条件

6.2.3:

- core: 修复 eval 代码的源映射处理，这表现为未处理的异常被吞下，例如在运行 frida-trace 时
- core: 修复 Python 3.x 构建系统回归
- frida-trace: 修复路径转义问题
- frida-trace: 改进坏处理程序的错误处理

6.2.4:

- frida-trace: 监视处理程序而不是轮询它们

6.2.5:

- core: 添加对通过使用函数而不是回调对象调用 *Interceptor.attach()* 来 hook 任意指令的支持
- core: 添加对分离由 *Interceptor.attach()* 添加的单个监听器的支持，甚至可以从它们的回调中同步分离
- core: 添加 *Memory.scanSync()*
- core: 通过改进 *Interceptor* 以在 ARM 上保留 *r12* 又名 *IP* 来修复破坏
- core: 向 JavaScript 运行时公开 *r8* 到 *r12*
- core: 修复在不支持未对齐字访问的架构上的崩溃
- frida-repl: 通过使用 RPC 功能简化逻辑
- node: 升级到预构建 3.x

6.2.6:

- core: 修复非越狱 iOS 系统上的回归
- core: 修复 Duktape 运行时中的 Interceptor 回归
- core: 修复已解析导入的模块名称
- core: 添加用于指定要连接的主机的 API
- core: 改进 QNX 支持并修复构建回归
- core: 修复 Mac 上的 frida-inject 构建系统
- core: (Windows) 修复 USB 设备位置检索失败时的崩溃
- frida-server: 允许覆盖默认监听地址
- frida-node: 向 DeviceManager 添加 *addRemoteDevice()* 和 *removeRemoteDevice()*
- frida-python: 添加 -H 开关用于指定要连接的主机
- frida-python: 向 DeviceManager 添加 *add_remote_device()* 和 *remove_remote_device()*
- frida-python: 修复与 Duktape 运行时的兼容性问题
- frida-python: 规范化请求的 RPC 方法名称

享受吧！
