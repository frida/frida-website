---
layout: news_item
title: 'Frida 16.0.0 发布'
date: 2022-10-08 02:00:19 +0200
author: oleavr
version: 16.0.0
categories: [release]
---

希望你们中的一些人正在享受 frida.Compiler！如果您不知道那是什么，请查看 [15.2.0 release notes][]。

## 性能

早在 15.2.0 中，frida.Compiler 就有一些让我困扰的地方：即使在我的 i9-12900K Linux 工作站上，编译一个微小的“Hello World”也需要几秒钟：

{% highlight bash %}
$ time frida-compile explore.ts -o _agent.js

real	0m1.491s
user	0m3.016s
sys	0m0.115s
{% endhighlight %}

经过大量的 [profiling][] 和疯狂的 yak shaving，我终于达到了这个目标：

{% highlight bash %}
$ time frida-compile explore.ts -o _agent.js

real	0m0.325s
user	0m0.244s
sys	0m0.109s
{% endhighlight %}

这真是天壤之别！这意味着诸如 `frida -l explore.ts` 之类的即时编译用例现在更加流畅。更重要的是，这意味着基于 Frida 的工具可以以这种方式加载用户脚本，而无需让用户忍受几秒钟的启动延迟。

## 快照

您可能想知道我们是如何使编译器启动得如此之快的。如果您查看底层，您会发现它使用了 TypeScript 编译器。这是在启动时解析和运行的大量代码。此外，加载和处理定义所有涉及类型的 .d.ts 文件实际上更加昂贵。

我们在 15.2 中实施的第一个优化是简单地使用我们的 V8 运行时（如果可用）。仅此一项就给了我们很好的速度提升。然而，经过一番分析，很明显 V8 意识到一旦我们开始处理 .d.ts 文件，它就在处理繁重的工作负载，这导致它花费大量时间来优化 TypeScript 编译器的代码。

这让我想起了一个很久以前注意到的非常酷的 V8 功能：[custom startup snapshots][]。基本上，如果我们能提前预热 TypeScript 编译器并在构建 Frida 时预先创建所有的 .d.ts 源文件，我们就可以在那时对 VM 的状态进行快照，并嵌入生成的启动快照。然后在运行时，我们可以从快照启动并立即运行。

作为实现此功能的一部分，我扩展了 GumJS，以便可以将快照与代理的源代码一起传递给 create_script()。还有 snapshot_script()，用于首先创建快照。

例如：

{% highlight python %}
import frida

session = frida.attach(0)

snapshot = session.snapshot_script("const example = { magic: 42 };",
                                   warmup_script="true",
                                   runtime="v8")
print("Snapshot created! Size:", len(snapshot))
{% endhighlight %}

然后可以将此快照保存到文件，稍后像这样加载：

{% highlight python %}
script = session.create_script("console.log(JSON.stringify(example));",
                               snapshot=snapshot,
                               runtime="v8")
script.load()
{% endhighlight %}

请注意，快照需要在以后加载它们的相同 OS/架构/V8 版本上创建。

## V8 10.x

另一个令人兴奋的消息是我们已将 V8 升级到 10.x，这意味着我们可以享受最新的 VM 改进和 JavaScript 语言功能。考虑到我们上次升级是在两年多以前，这次绝对是一个可靠的升级。

## 多重构建系统的诅咒，第二部分

您可能还记得 [15.1.15 release notes][]，我们比以往任何时候都更接近达到所有 Frida 都可以使用单个构建系统构建的里程碑。那时剩下的唯一组件是 V8，我们以前使用 Google 的 GN 构建系统来构建它。我很高兴地报告，我们终于达到了那个里程碑。我们现在为 V8 提供了一个全新的 Meson 构建系统。耶！

## EOF

还有很多其他令人兴奋的更改，所以一定要查看下面的变更日志。

享受吧！

### 变更日志

- compiler: 使用快照减少启动时间。
- compiler: 升级 frida-compile 和其他依赖项。
- 添加对 JavaScript VM 快照的支持。这仅由 V8 后端实现，因为 QuickJS 目前不支持此功能。
- 将调试器 API 从 Session 移动到 Script。这是必要的，因为 V8 的调试器基于每个 Isolate 工作，而我们现在每个 Script 需要一个 Isolate 才能支持快照。
- server+portal: 修复守护进程父级就绪失败退出。感谢 [@pachoo][]！
- resource-compiler: 添加对压缩的支持。我们将此用于 frida.Compiler 的堆快照。
- ipc: 增加 UNIX 套接字缓冲区大小以提高吞吐量。
- meson: 将 frida-payload 提升为公共 API。这允许为 frida-agent 和 frida-gadget 不适用的用例实现自定义有效载荷。
- windows: 迁移到 Visual Studio 2022。
- windows: 将工具链/SDK 逻辑移动到使用粒度 SDK。
- windows: 不依赖 .py 文件关联。
- darwin: 修复与 macOS 13 和 iOS >= 15.6.1 的兼容性。
- darwin: 如果存在，使用 Apple 的 libffi-trampolines.dylib，以便我们可以支持 iOS 15 及更高版本。感谢有趣的结对编程会议，[@hsorbo][]！
- fruity: 修复 USBMUXD_SOCKET_ADDRESS 的处理。感谢 [@0x3c3e][]！
- fruity: 放弃对 USBMUXD_SERVER_\* 环境变量的支持。感谢 [@as0ler][]！
- droidy: 改进 ADB 环境变量的处理。感谢 [@0x3c3e][]！
- java: (android) 修复 Android 11 & 12 上的 ClassLinker 偏移检测 (#264)。感谢 [@sh4dowb][]！
- java: (android) 修复 Android 13 上的早期插桩。
- java: 处理以 *$* 为前缀的方法和字段。感谢 [@eybisi][]！
- android: 迁移到 NDK r25。
- arm64: 优化内存复制实现。
- stalker: 确保 EventSink 在拆卸时停止。
- stalker: 修复分支涉及移位时的 ARM 堆栈破坏。
- stalker: 处理涉及移位寄存器的 ARM PC 加载。
- stalker: 应用回补时通知 ARM 观察者。
- stalker: 收到通知时应用 ARM 回补。
- stalker: 添加对 switch 块回调的 ARM 支持。
- arm-reader: 公开 disassemble_instruction_at()。
- thumb-reader: 公开 disassemble_instruction_at()。
- memory: 根据当前 V8 语义重新调整 API。
- gumjs: 将 V8 后端移动到每个脚本一个 Isolate。
- gumjs: 支持使用环境变量传递 V8 标志：FRIDA_V8_EXTRA_FLAGS。
- gumjs: 在 Darwin/arm\* 上使用 V8 写保护。
- gumjs: 添加对动态定义脚本的支持。
- prof: 支持 Linux/MIPS 上的旧系统头文件。
- devkit: 改进 UNIX 上的示例编译文档。
- ci: 将剩余的旧版 CI 迁移到 GitHub Actions。
- quickjs: 修复模块评估期间出错时的 use-after-free。
- v8: 升级到最新的 V8 10.x。
- v8: 添加 Meson 构建系统。
- usrsctp: 将 Windows 要求降低到 XP，就像我们的其他组件一样。
- xz: 避免 ANSI 时代的 Windows API。
- libc-shim: 支持 Linux/MIPS 上的旧系统头文件。
- glib: 为 MIPS 添加 Linux libc 回退。
- 添加 config.mk 选项以能够禁用 Android 上的模拟代理，从而允许构建更小的二进制文件。感谢 [@muhzii][]！
- python: 放弃 Python 2 支持，现代化代码，添加文档字符串，类型提示，添加具有现代工具的 CI，以及许多其他好东西。感谢 [@yotamN][]！
- python: 构建 Python wheels 而不是 eggs。感谢 [@oriori1703][]！
- python: 修复 Device.get_bus()。以前的实现调用了不存在的 \_Device.get_bus()。感谢 [@oriori1703][]！
- python: 迁移到稳定的 Python C API。
- python: 添加对从源代码构建的支持，使用 frida-core devkit。
- python: 添加对新快照 API 的支持。
- node: 添加对新快照 API 的支持。
- node: 修复 Electron v20 兼容性。


[15.2.0 release notes]: {% post_url _i18n/cn/2022-07-21-frida-15-2-0-released %}
[profiling]: https://github.com/frida/frida-core/blob/155328df3420ead34e485f1c4fb7e5b3fe7d71a6/tests/profile-compiler.sh
[custom startup snapshots]: https://v8.dev/blog/custom-startup-snapshots
[15.1.15 release notes]: {% post_url _i18n/cn/2022-02-01-frida-15-1-15-released %}
[@pachoo]: https://github.com/pachoo
[@hsorbo]: https://twitter.com/hsorbo
[@0x3c3e]: https://github.com/0x3c3e
[@as0ler]: https://twitter.com/as0ler
[@sh4dowb]: https://github.com/sh4dowb
[@eybisi]: https://github.com/eybisi
[@muhzii]: https://github.com/muhzii
[@yotamN]: https://github.com/yotamN
[@oriori1703]: https://github.com/oriori1703
