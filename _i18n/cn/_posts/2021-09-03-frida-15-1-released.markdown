---
layout: news_item
title: 'Frida 15.1 发布'
date: 2021-09-03 12:00:00 +0200
author: hot3eed
version: 15.1
categories: [release]
---

介绍 _全新的_ Swift 桥接！既然 Swift 自版本 5 以来已经是 ABI 稳定的，这个期待已久的桥接允许 Frida 与用 Swift 编写的二进制文件很好地配合。无论您 [consider][] Swift 是静态语言还是动态语言，有一件事是肯定的，随着这个 Frida 版本的发布，它变得更加动态了。

## 元数据

逆向工程师在开始逆向二进制文件时做的第一件事可能就是了解二进制文件定义的不同数据结构。因此，首先构建相当于 `ObjC.classes` 和 `ObjC.protocols` API 的 Swift 等效项是最有意义的。但是，由于 Swift 具有其他一等类型，即结构体和枚举，并且由于 Swift 运行时不提供反射原语，至少不像 Objective-C 那样，这意味着我们必须挖掘得更深一点。

幸运的是，Swift 编译器为二进制文件定义的每种类型发出元数据。在撰写本文时，此元数据捆绑在 `TargetTypeContextDescriptor` C++ 结构中，定义在 [include/swift/ABI/Metadata.h][] 中。此数据结构包括类型名称、其字段、其方法（如果适用）以及取决于手头类型的其他有用数据。这些数据结构由相对指针指向（定义在 [include/swift/Basic/RelativePointer.h][] 中）。在 Mach-O 二进制文件中，这些存储在 `__swift5_types` 部分中。

因此，要转储类型，Frida 基本上会迭代这些数据结构并沿途解析它们，这与 [dsdump][] 所做的非常相似，除了您不必为了修补它而构建 Swift 编译器。

Frida 还具有能够探测用 Swift 编写的内部 Apple dylib 的优势，这是因为我们不需要解析 `dyld_shared_cache`，这要归功于私有的 `getsectiondata` API，它让我们轻松获得部分偏移量。

一旦我们有了元数据，我们就能够轻松地为对象实例和不同类型的值创建 JavaScript 包装器。

## 约定

为了与 Objective-C 桥接相提并论，Swift 桥接必须支持调用 Swift 函数，这也被证明不是那么简单。

Swift 定义了自己的调用约定 `swiftcall`，简而言之，它试图尽可能高效。这意味着，不要在小于 4 个寄存器大小的结构体上浪费加载和存储指令。也就是说，直接在寄存器中传递这些类型的结构体。由于这可能会很快超额预订我们宝贵的 8 个参数寄存器（在 AARCH64 上为 `x0`-`x7`），它不使用第一个寄存器作为 `self` 参数。它还定义了一个 `error` 寄存器，被调用者可以在其中存储它们抛出的错误。

我们上面刚刚描述的内容在 Swift 编译器文档中被称为“物理降级”，它由后端 LLVM 实现。

物理降级之前的过程称为“语义降级”，即编译器前端弄清楚谁“拥有”一个值以及它是直接的还是间接的。有些结构体，即使它们可能小于 4 个寄存器，也必须间接传递，因为例如，它们是泛型的，因此它们的确切内存布局在编译时是未知的，或者因为它们包含必须始终在内存中的弱引用。

我们必须实现语义和物理降级才能调用 Swift 函数。物理降级是使用 JIT 编译的适配器函数实现的（感谢 `Arm64Writer` API），它执行必要的 `SystemV`-`swiftcall` 转换。语义降级是通过利用类型的元数据来确定我们是否应该直接传递值来实现的。

编译器 [docs][] 是了解有关调用约定的更多信息的绝佳资源。

## 拦截

因为 Swift 直接在寄存器中传递结构体，所以在寄存器和实际参数之间没有 1 对 1 的映射。

现在我们有了类型的 JavaScript 包装器，并且能够从 JS 运行时调用 Swift 函数，下一步很好的做法是扩展 `Interceptor` 以支持 Swift 函数。

对于未剥离的函数，我们使用简单的正则表达式来解析参数类型和名称，返回值也是如此。解析它们之后，我们检索类型元数据，弄清楚类型的布局，然后简单地为每个参数构造 JS 包装器，我们将 Swift 参数值传递给它，无论它占用多少个寄存器。

## EOF

请注意，该桥接仍处于开发的早期阶段，因此：
  - 目前仅支持 Darwin arm64(e)。
  - 性能尚未达到最佳状态，某些边缘情况可能无法正确处理，并且可能会出现一些错误。
  - API 有可能在短期到中期内以破坏性方式更改。
  - 非常欢迎 PR 和问题！

请参阅 [documentation][] 以获取有关当前 API 的最新资源。

享受吧！


### 15.1.0 中的变化

- 实现 Swift 桥接，允许 Frida：
  - 探索 Swift 模块以及在其中实现的类型，即类、结构体、枚举和协议。
  - 为对象实例和值创建 JavaScript 包装器。
  - 从 JavaScript 运行时调用使用 `swiftcall` 调用约定的函数。
  - 拦截 Swift 函数并自动解析其参数和返回值。
- 修复 i/macOS 回归，其中与 iOS 15 支持相关的更改最终破坏了对附加到 Apple 系统守护程序的支持。
- gadget: 在连接模式下添加 interaction.parameters。然后，这些参数被“反射”到 `parameters.config` 下的应用程序信息中。感谢 [@mrmacete][]！

### 15.1.1 中的变化

- gumjs: 修复 V8 运行时中的 Swift 生命周期逻辑。

### 15.1.2 中的变化

- control-service: 修复信号接线，以便 Device.output 等信号由远程 frida-server 正确发出。感谢 [@mrmacete][]！
- gadget: 修复“runtime”选项，该选项在导致 Frida 15 的重构期间被遗忘了。
- relocator: 优化 x86 RIP 相对代码的处理，通过尽可能简单地调整偏移量。
- gumjs: 添加 ESM 支持，以便像 frida-compile 这样的工具可以输出更好的代码。
- gumjs: 解析后丢弃源代码。
- gumjs: 编译为 QuickJS 字节码时堵塞泄漏。
- java: 公开 JNIEnv->GetDirectBufferAddress。感谢 [@pandasauce][]！

### 15.1.3 中的变化

- objc: 修复 Proxy respondsToSelector 实现。感谢 [@hot3eed][]！
- gumjs: 修复模块丢失时 V8 运行时的崩溃。
- gumjs: 发出由 ESM 入口点抛出的 V8 异常。

### 15.1.4 中的变化

- gumjs: 修复 QuickJS 运行时中与弱引用回调相关的双重释放。感谢 [@mrmacete][]！
- gumjs: 在不相关的 NativeCallback 调用中忽略 Interceptor 上下文。通过这种方式，来自调用堆栈更高处的无效 Interceptor 上下文将被安全地忽略，而有利于最小但正确的回调上下文。感谢 [@mrmacete][]！
- gumjs: 修复 ESM 模块名称规范化逻辑。
- gumjs: 为 cwd、home 和 tmp 目录添加 Process getter。
- swift: 将元数据缓存性能提高约 3 倍。感谢 [@hot3eed][]！
- node: 发布 v15 而不是 v13 的 Electron 预构建。

### 15.1.5 中的变化

- gumjs: 修复 QuickJS 字符串化大数字时的崩溃。感谢 [@vfsfitvnm][]！
- gumjs: 向 CModule 公开 GError 和 GIConv。感谢 [@0xDC00][]！
- droidy: 支持 ADB 服务器主机/端口环境变量。感谢 [@amirpeles90][]！
- swift: 改进非 Darwin 上的加载行为。

### 15.1.6 中的变化

- swift: 修复非 Darwin 上加载期间的崩溃。感谢 [@hot3eed][]！

### 15.1.7 中的变化

- swift: 修复旧操作系统版本上的 CoreSymbolication 集成。感谢 [@hot3eed][]！
- python: 为 Android/ARM 添加 setup.py 下载逻辑。不过，我们的 CI 尚未构建和上传此类二进制文件。

### 15.1.8 中的变化

- darwin: 添加对在 SRD 环境中工作的支持。感谢 [@Nessphoro][]！
- darwin: 添加对使用较新 iOS SDK 构建的支持。

### 15.1.9 中的变化

- x86-relocator: 修复 RIP 相对指令的修补。这是 15.1.2 中引入的回归，导致 Stalker 变得不可靠。
- portal-service: 每当从 PortalService 取消设置会话 ID 时，始终删除 ClusterNode 会话。这避免了 NULL 解引用和泄漏。感谢 [@mrmacete][]！
- frida-portal: 修复 --help 输出中的拼写错误。

### 15.1.10 中的变化

- p2p: 优雅地处理不支持的 ICE 候选者。
- p2p: 暂时禁用 ICE-TCP。
- p2p: 重做 PeerSocket 以修复同步问题。
- socket: 修复 WebService 拆除。
- vala: 优化服务器端 GDBus 回复处理。这意味着我们的 RPC 和网络协议变得不那么健谈/性能更高。
- x86-writer: 在间接分支之后/之中添加 UD2 指令。
- x86-writer: 尽可能发出更大的 NOP。
- stalker: 改进 x86/64 后端的性能。
- objc-api-resolver: 防止已处置的 ObjC 类。感谢 [@mrmacete][]！
- gumjs: 修复 V8 Interceptor.{replace,revert}() 回归。感谢 [@3vilWind][]！
- gumjs: 使用 regsAccessed 和 operand.access 扩展 Instruction API。感谢 [@3vilWind][]！

### 15.1.11 中的变化

- x86-writer: 添加 put_sahf() 和 put_lahf()。
- x86-relocator: 修复超出范围的 Jcc 分支目标的处理。感谢 [@0xDC00][]！
- stalker: 优化目标地址检索。
- stalker: 避免昂贵的 XCHG 指令。
- stalker: 优化 IC 序言以使用 SAHF/LAHF。
- memory: 改进 scan() 以支持正则表达式模式。感谢 [@hot3eed][]！
- kernel: 在支持的地方从 all_image_info 获取基址。感谢 [@mrmacete][]！
- windows: 提高 dbghelp backtracer 的可靠性。感谢 [@HonicRoku][]！

### 15.1.12 中的变化

- agent: 修复在 NO_REPLY_EXPECTED 调用卸载时的挂起，我们会等待发送回复。由于服务器端 DBus 代码由 Vala 编译器生成，并且它以前（在 Frida <= 15.1.9 中）忽略 NO_REPLY_EXPECTED，因此此错误未被注意到。
- android: 迁移到 NDK r24 Beta 1。

### 15.1.13 中的变化

- linux: 改进 glibc 系统上的模块解析。
- fruity: 修复 dyld v4 案例（越狱 iOS 15.x）上的 spawn。感谢 [@mrmacete][]！
- objc-api-resolver: 通过互斥锁防止 objc_disposeClassPair()。感谢 [@mrmacete][]！
- gumjs: 更新 Kernel.scan\*() 以匹配 Memory.scan\*()。感谢 [@hot3eed][]！
- stalker: 修复 x86 上发出的分支操作码。
- stalker: 修复 Thumb IT AL 的处理。
- stalker: 在 x86 上通过 PLT 处理排除的 Linux 调用。
- stalker: 修复 x86 上的 Linux 异常处理。
- java: 添加 Java.backtrace()，目前没有任何 API 稳定性保证。

### 15.1.14 中的变化

- backtracer: 改进模糊回溯器以也包括直接调用者，并在已知时避免走过堆栈末尾。
- windows: 实现 Thread.try_get_ranges()。
- linux: 实现 Thread.try_get_ranges()。
- ios: 在 SRD 系统上与 launchd 签到。
- stalker: 修复 x86 上调用深度代码中的意外破坏。
- node: 也发布 v17 的 Node.js 预构建。


[consider]: https://youtu.be/0rHG_Pa86oA?t=36
[include/swift/ABI/Metadata.h]: https://github.com/apple/swift/blob/52e852a7a9758e6edcb872761ab997b552eec565/include/swift/ABI/Metadata.h
[dsdump]: https://github.com/DerekSelander/dsdump
[include/swift/Basic/RelativePointer.h]: https://github.com/apple/swift/blob/52e852a7a9758e6edcb872761ab997b552eec565/include/swift/Basic/RelativePointer.h
[docs]: https://github.com/apple/swift/blob/52e852a7a9758e6edcb872761ab997b552eec565/docs/ABI/CallingConvention.rst
[documentation]: https://github.com/frida/frida-swift-bridge/blob/master/docs/api.md
[@mrmacete]: https://twitter.com/bezjaje
[@pandasauce]: https://github.com/pandasauce
[@hot3eed]: https://github.com/hot3eed
[@vfsfitvnm]: https://github.com/vfsfitvnm
[@0xDC00]: https://github.com/0xDC00
[@amirpeles90]: https://github.com/amirpeles90
[@Nessphoro]: https://github.com/Nessphoro
[@3vilWind]: https://github.com/3vilWind
[@HonicRoku]: https://github.com/HonicRoku
