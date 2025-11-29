---
layout: news_item
title: 'Frida 12.9 发布'
date: 2020-05-19 22:00:00 +0200
author: oleavr
version: 12.9
categories: [release]
---

我们之前的重大发布都是关于 [Stalker][] 的。对于那些还不熟悉它的人来说，它基本上是一个代码跟踪引擎 —— 允许跟踪线程，捕获每个函数、每个块，甚至执行的每条指令。除了跟踪代码之外，它还允许您在任何地方添加和删除指令。它甚至使用高级 JIT 技巧来使所有这些变得非常快。

这听起来可能还有点抽象，所以让我们看几个例子。使用它的一种方法是当您想确定“[what other functions does this function call][]”时。或者，也许您想使用 Apple 的语音合成器在属于应用程序的代码中的每个 RET 指令处宣布 RAX 寄存器的值？[Here][] 是如何做到的。这是我早在 2017 年 [r2con presentation][] 上的演示之一。

直到现在，Stalker 仅在 Intel 架构和 ARM64 上可用。所以我很高兴地宣布 Stalker 现在也可以在 ARM32 上使用了！耶！🎉 我希望这个被严重怀念的 Stalker 后端能激励你们中的许多人开始在 Stalker 之上构建非常酷的东西。我觉得除了“仅仅”代码跟踪之外，它还有很大的潜力。结合 [CModule][]，平衡快速原型设计和动态行为与性能变得非常容易。

在这个版本中有很多要谈的。其他主要变化之一是我们升级了所有依赖项。其中最有趣的可能是 V8，我们将它升级到了 8.4。这意味着您可以使用所有最新的 JavaScript 语言功能，例如 [optional chaining][] 和 [nullish coalescing operator][]，而无需 [frida-compile][] 您的 agent。此外，还有性能改进，这是 V8 不断变得越来越好的另一个领域。

我们还刚刚添加了对 Android 11 Developer Preview 4 的支持，并且 iOS/arm64e 应用程序现在即使在受限 iOS 上也完全受支持。在我们所有支持的平台上的情况都有了很大改善。我想特别强调的一件事是，我们终于消除了一个影响我们基于 Duktape 的 JS 运行时的长期资源 [leak][] —— 这是一个自从我们使用 Duktape 作为默认 JS 运行时以来就一直存在的错误。

无论如何，真的没有简单的方法来深入挖掘所有改进的领域，所以一定要查看下面的变更日志。

享受吧！


### 12.9.0 中的变化

- Stalker 现在也可以在 ARM32 上使用。🎉
- Stalker JS 集成不再破坏 *errno* / *LastError*。
- *Stalker.follow()* 现在在 x86 和 ARM64 上是可靠的，包括当目标线程在 Windows 上处于系统调用中时。
- Stalker 终于在 WoW64 上可靠了。感谢 [@zuypt][]！
- 所有依赖项已更新到最新最好的版本。最令人兴奋的是 V8 8.4，支持最新的 JavaScript 语言功能。
- 长期存在的 Duktape 内存泄漏终于被发现并修复。感谢 [@disazoz][] 的错误报告导致了这一突破。
- *Socket.connect()* 出错时不再泄漏文件描述符（及相关内存）。（通过 GLib 依赖项升级修复。）感谢报告，[@1215clf][]！
- *Kernel.read\*()* 不再在 V8 运行时中泄漏。
- UNIX 构建系统迁移到 Meson 0.54。
- Windows 构建系统迁移到 VS2019。
- 除了 v10 和 v12 之外，还为 v14 提供了 Node.js 预构建。
- 为 v8 和 v9 提供了 Electron 预构建。
- F32 的 Fedora 软件包。
- Ubuntu 20.04 的 Ubuntu 软件包。
- Python 绑定不再使用任何已弃用的 API。
- 支持仅 leanback 的 Android 应用程序。感谢 [@5murfette][]！
- iOS 受限 spawn() w/o closure 在 arm64e 上受支持。感谢 [@mrmacete][]！
- iOS usbmux 配对记录 plist 解析现在也处理二进制 plist，修复了一个长期存在的问题，即 Frida 会拒绝系留的 iOS USB 设备。感谢 [@pachoo][]！
- *ObjC.choose()* 也在 arm64e 上受支持。感谢 [@mrmacete][]！
- *ObjC.protocols* 枚举终于正常工作，而不仅仅是第一次。感谢报告，[@CodeColorist][]！
- 对 Android 11 Developer Preview 的初步支持。感谢 [@abdawoud][]！
- MUSL libc 兼容性。
- 支持旧版本的 glibc，因此我们的二进制文件可以在各种桌面 Linux 系统上运行。
- Libc shim 还涵盖 *memalign()* 并支持较新的 GNU 工具链。
- Exceptor 的 POSIX 后端现在可以在 ARM32 上正确检测 Thumb，这以前会导致随机崩溃。
- Exceptor 不再破坏 i/macOS 上的“rflags” (x86_64) 和“cpsr” (ARM64)，并提供对本机上下文的写访问权限。
- 向 libc shim 添加了四个基本的 i/macOS 64 位系统调用：*read()*, *write()*, *mmap()*, *munmap()*。感谢 [@mrmacete][]！
- 为了方便起见，iOS 二进制文件现在使用“skip-library-validation”权利进行签名。感谢 [@elvanderb][]！
- frida-core Vala API 绑定不再缺少 *frida.Error* 类型。
- 我们的脚本现在允许在处于 *LOADING* 状态时向它们 *post()* 消息。这在脚本需要在 *load()* 期间发出同步请求时很有用。感谢 [@Gbps][]！
- Gadget 终于支持在 64 位 ELF 目标上使用 V8 运行时进行早期插桩，以前构造函数会以错误的顺序运行。感谢 [@tacesrever][]！
- 支持 *Device.open_channel()* 中除 TCP 之外的 ADB 通道。感谢 [@aemmitt-ns][]！
- *ArmWriter* 和 *ThumbWriter* API 中支持许多新指令。
- 对我们的 ARM32 重定位器实现进行了大量改进。
- 通过加载器调用时 Linux 模块枚举正常工作。
- Linux 符号解析改进。
- V8 运行时中更好的参数列表处理，将 *undefined* 视为与 Duktape 运行时相同。感谢 [@mrmacete][]！
- CModule Stalker API 恢复正常工作。
- CModule 运行时现在公开 *Thread.{get,set}_system_error()*。
- CModule 现在是 Linux/MIPS 上的存根，而不是由于 TinyCC 尚不支持 MIPS 而导致编译失败。
- Capstone 配置为支持 ARMv8 A32 编码。

### 12.9.1 中的变化

- Python 绑定的 setup.py 对 macOS 上的 Python 3.x 执行正确的操作。

### 12.9.2 中的变化

- Fruity (iOS USB) 后端不再在 stdio 上发出警告。

### 12.9.3 中的变化

- 现在支持 Android 11 Developer Preview 4。感谢协助，[@enovella_][]！
- Linux 文件监控恢复良好状态。
- ArmRelocator 正确重定位涉及 PC 寄存器的 ADD 指令。
- ThumbRelocator 正确处理包含无条件分支的 IT 块。这意味着 Interceptor 能够 hook 更多棘手的情况。感谢 [@bet4it][]！
- Stalker ARM32 还支持 Thumb 模式下的 clone 系统调用。
- Stalker ARM32 现在像 ARM64 后端一样抑制独占操作周围的事件。
- Stalker ARM32 信任阈值支持。
- 改进 ObjC 和 Java 桥接中的错误处理，以避免在不受支持的操作系统上使进程崩溃。

### 12.9.4 中的变化

- *ObjC.available* 不再假装 Objective-C 运行时可用，而实际上不可用。12.9.3 中的错误处理重构破坏了这一点，并且由于这是我们测试覆盖率的盲点，因此回归未被注意到。
- Electron v9 已经发布，所以我们现在只提供 v9 的预构建。

### 12.9.5 中的变化

- iOS 早期插桩 —— 即 spawn() —— 在最新的 unc0ver 上受支持。
- iOS 崩溃报告器集成移植到 iOS 13.5。
- *SystemFunction* 现在在 Duktape 运行时中实现 *call()* 和 *apply()*，而不仅仅是在 V8 运行时中。
- Java 桥接终于处理带有嵌入 nul 的字符串，修复了一个与 Java 桥接存在一样久的长期问题。感谢 [@tacesrever][]！

### 12.9.6 中的变化

- 这次除了正确的 Windows 二进制文件外没有其他更改。Windows CI worker 上次实际上没有构建任何东西，并发布了陈旧的二进制文件。

### 12.9.7 中的变化

- iOS 早期插桩在 unc0ver 越狱上更可靠：我们现在作为早期插桩的一部分加载 *substrate-inserter.dylib*。这意味着它有机会引导进程，并让您 hook 引导程序 hook 的系统 API，而不必担心引导程序在遇到您的 hook 时会感到困惑。感谢 [@mrmacete][]！

### 12.9.8 中的变化

- ApiResolver 实现现在通过将“/i”附加到查询字符串来支持不区分大小写的匹配。感谢 [@Hexploitable][]！
- *module* ApiResolver 不再泄漏 *MatchInfo* 实例。
- CModule 运行时获得了 *GLib.PatternSpec* 和 GLib UTF-8 大小写助手。
- 引入 *DebugSymbol.load()* 以便能够显式加载调试符号。目前这仅在 Windows 上实现，我们现在还支持“module!symbol”表示法以提高性能和精度。感谢 [@ohjeongwook][]！
- Java 桥接获得了一个全新的 API：*Java.enumerateMethods(query)* 这使得能够有效地定位与给定查询匹配的方法。
- *ObjC.choose()* 不再因仅在我们的 V8 运行时中可重现的生命周期问题而崩溃。


[Stalker]: /docs/stalker/
[what other functions does this function call]: https://codeshare.frida.re/@oleavr/who-does-it-call/
[Here]: https://github.com/frida/frida-presentations/blob/master/R2Con2017/02-transforms/06-return-values.js
[r2con presentation]: https://youtu.be/sBcLPLtqGYU
[CModule]: /docs/javascript-api/#cmodule
[optional chaining]: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Optional_chaining
[nullish coalescing operator]: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Nullish_coalescing_operator
[frida-compile]: https://github.com/oleavr/frida-agent-example
[leak]: https://github.com/svaarala/duktape/pull/2282
[@zuypt]: https://github.com/zuypt
[@disazoz]: https://github.com/disazoz
[@1215clf]: https://github.com/1215clf
[@5murfette]: https://github.com/5murfette
[@mrmacete]: https://twitter.com/bezjaje
[@pachoo]: https://github.com/pachoo
[@CodeColorist]: https://twitter.com/CodeColorist
[@abdawoud]: https://github.com/abdawoud
[@elvanderb]: https://twitter.com/elvanderb
[@Gbps]: https://github.com/Gbps
[@tacesrever]: https://github.com/tacesrever
[@aemmitt-ns]: https://github.com/aemmitt-ns
[@enovella_]: https://twitter.com/enovella_
[@bet4it]: https://github.com/bet4it
[@Hexploitable]: https://twitter.com/Hexploitable
[@ohjeongwook]: https://twitter.com/ohjeongwook
