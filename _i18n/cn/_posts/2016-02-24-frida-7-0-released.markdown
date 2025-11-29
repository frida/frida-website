---
layout: news_item
title: 'Frida 7.0 发布'
date: 2016-02-24 04:00:00 +0100
author: oleavr
version: 7.0
categories: [release]
---

距离我们上一次主要版本发布已经有一段时间了。这次我们解决了长期存在的问题，即 64 位整数被表示为 JavaScript Number 值。这意味着超过 53 位的值是有问题的，因为底层表示是 double。

*Memory*、*NativeFunction* 和 *NativeCallback* API 中的 64 位类型现在由新引入的 [Int64](/docs/javascript-api/#int64) 和 [UInt64](/docs/javascript-api/#uint64) 类型正确表示，它们的 API 几乎与 [NativePointer](/docs/javascript-api/#nativepointer) 相同。

现在让我们祈祷 int64/uint64 [进入 ES7](https://twitter.com/BrendanEich/status/526826278377099264)。

最后，这是更改的摘要：

7.0.0:

- core: 重做 64 位整数的处理
- core: 提高构造函数的严格性
- core: 改进 QNX 支持
- frida-repl: 更新徽标

7.0.1:

- core: 修复 32 位架构上的 Int64/UInt64 字段容量

7.0.2:

- core: 允许将 Int64 和 UInt64 原样传递给所有相关 API
- core: 修复 ObjC 实例上 $protocols 的处理

7.0.3:

- core: 修复监听器在调用中途被销毁的竞争条件
- core: 修复嵌套本机异常范围的处理
- core: 改进 QNX 支持
- frida-repl: 调整启动消息

7.0.4:

- core: 大幅提高 32 位 ARM 上的函数 hook 成功率
- core: 提高 64 位 ARM 上的函数 hook 成功率
- core: 修复 Interceptor 在 32 位 ARM 上公开的 *sp* 值

7.0.5:

- core: 在启动 iOS 应用程序时等待 *Device#resume()* 时旋转主 CFRunLoop，允许从主线程应用线程敏感的早期插桩

7.0.6:

- core: 修复 32 位 ARM 上半字对齐函数的 hook
- core: 修复 Linux 上的线程枚举
- core: 向 Script 运行时添加简单的 *hexdump()* API
- core: 使 Duktape 运行时的 CpuContext 可序列化为 JSON

7.0.7:

- core: 允许将 *NativePointer* 传递给 *hexdump()*

7.0.8:

- core: 修复 `retval.replace()` 中包装对象的处理
- core: 修复指定大小时 Memory.readUtf8String() 的行为
- core: 添加对 iOS 9.1 JB 上新的 *task_for_pid(0)* 方法的支持
- core: 不使用 *cbnz*，它在某些处理器上的 ARM 模式下不可用
- core: 为 QNX 实现 *enumerate_threads()* 和 *modify_thread()*

7.0.9:

- core: 修复在 iOS 上使用 *ios-deploy* 和其他我们在 *CoreFoundation* 之前加载的环境运行时 FridaGadget.dylib 中的早期崩溃
- core: 在 Darwin 上 *frida-helper* 的主线程中运行 *CFRunLoop*，允许系统会话脚本使用更多 Apple API
- core: 添加用于处理 GIO 流的流 API，目前仅通过 UnixInputStream 和 UnixOutputStream (UNIX) 以及 Win32InputStream 和 Win32OutputStream (Windows) 公开

7.0.10:

- core: 修复 I/O 操作挂起时脚本卸载时的死锁

7.0.11:

- core: 当 FridaGadget.dylib 阻塞等待 *Device#resume()* 时旋转主 CFRunLoop，允许从主线程应用线程敏感的早期插桩
- java: 修复方法类型健全性检查

享受吧！
