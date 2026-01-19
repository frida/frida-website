---
layout: news_item
title: 'Frida 14.2 发布'
date: 2021-02-10 10:00:00 +0200
author: oleavr
version: 14.2
categories: [release]
---

有很多要谈的。让我们从一个重要的新功能开始：

## Realms

Frida 支持 Android 已经有一段时间了，但有一个特定的功能一直被请求（主要）是那些认为自己看到了错误的用户。对话通常是这样开始的：“我在硬件加速的 Android 模拟器 X 中使用 Frida，当我 attach 到这个进程 Y 时，Process.enumerateModules() 缺少 JNI 库 Z。但我可以在 Process.enumerateRanges() 和 /proc/$pid/maps 中看到它。这是怎么回事？”

正如您可能已经猜到的那样，我们谈论的是 Android 的 NativeBridge，通常用于基于 Intel 的 Android 设备，以使它们能够运行仅支持 ARM 的应用程序 —— 即具有一个或多个仅为 ARM 构建的 JNI 组件的应用程序。

然而，在 Frida 上下文中，我们通常谈论的是运行为 x86 构建的 Android 系统的基于 VirtualBox 的模拟器。该系统随后附带由 libhoudini（专有 ARM 翻译器）提供支持的 NativeBridge 支持。

有很多这样的模拟器，例如 BlueStacks, LDPlayer, NoxPlayer 等。虽然提到的那些是为运行游戏而优化的，但现在也有 Google 官方的 Android 11 AVD，它们开箱即用地提供 NativeBridge 支持。

多年来，我一直在思考我们如何在 Frida 中支持这种情况，但思考它总是让我头疼。不过，这确实感觉像是我们应该在某个时候支持的东西，我只是很难弄清楚 API 会是什么样子。

然后到了 2020 年，Apple 宣布过渡到 ARM，突然 Rosetta 再次变得相关。“好吧”，我想，“现在我们有两个平台，在这些平台上支持包含运行遗留代码的模拟 realm 的进程将非常有用。”

是的，还有 Windows，但我们还不支持 ARM 上的 Windows。不过我们完全应该支持，所以如果有人有兴趣尝试一下，请*务必*联系我们。

无论如何，我很高兴地宣布，我们用于 x86 和 x86_64 的 Android 二进制文件现在开箱即用地支持此类进程。您可能已经熟悉以下 frida-core API，其中 Python 风格如下所示：

{% highlight python %}
session = device.attach(target)
{% endhighlight %}

（或者 *frida.attach()*，如果您的代码仅处理本地系统。）

如果 *target* 有一个模拟 realm，您现在可以这样做：

{% highlight python %}
session = device.attach(target, realm='emulated')
{% endhighlight %}

默认值为 `realm='native'`，实际上您可以同时使用两个 realm。当使用我们的 CLI 工具时，传递 `--realm=emulated` 以作用于模拟 realm。

在 Android 上使用此功能的一个重要警告是，您需要在 *native* realm 中应用 Java 级检测。

最后值得注意的是，这个新功能目前仅在 Android 上受支持，但以后支持 macOS 上的 Rosetta 应该不难。如果您想帮忙，请务必联系我们。

## 将 Android Java Hooking 内联

Frida 的 [Java bridge][] 在 Android 上替换 Java 方法的方式直到现在都是通过改变内存中的方法元数据来实现的，以便目标方法变为 native —— 如果它还不是的话。这允许我们安装一个与给定方法的 JNI 签名匹配的 NativeCallback。

这带来了一些挑战，因为 ART 运行时确实有其他依赖于给定方法个性的内部状态。我们设计了一些黑客手段来绕过其中一些问题，但一些特别棘手的边缘情况仍未解决。一个这样的例子是 ART VM 维护的 JIT 分析数据。

我一直在思考的一个想法是停止改变方法元数据，而是对 AOT 生成的机器代码执行内联 hook —— 对于非 native 方法而言。这仍然留下了在 VM 解释器上运行的方法，但假设我们可以通过 hook VM 内部来处理这些方法。

我尝试了一个早期原型来进一步探索这种方法。它似乎可行，但仍有许多挑战需要解决。在与 [@muhzii][] 进行了一些头脑风暴之后，他继续在业余时间进一步发展这个粗略的 PoC。然后有一天，当我看到他刚刚打开的惊人拉取请求时，我几乎兴奋得从椅子上摔下来。

感谢 Muhammed 的出色工作，您现在都可以在 Android 上享受大大改进的 Java 检测体验。这意味着提高了稳定性，也意味着直接调用不会绕过您的替换方法。耶！

## 去优化

对于那些在 Android 上使用 Java.deoptimizeEverything() 以确保您的 hook 不会因优化而被跳过的人，现在有一个更细粒度的替代方案。感谢 [@alkalinesec][] 对我们 Java bridge 的巧妙贡献，您现在可以使用 Java.deoptimizeBootImage()。它确保只有引导映像 OAT 文件中的代码被去优化。在某些情况下，这是一个严重的性能提升，在这些情况下，应用程序代码本身在去优化时很慢，并且为了可靠地命中 hook，不需要去优化它。

## CModule

这里还有另一个非常令人兴奋的更新。我们故事中的下一个英雄是 [@mephi42][]，他开始将 Frida 移植到 S390x。我们的 CModule 实现幕后依赖于 TinyCC，它尚不支持此架构。系统可能有一个 C 编译器，所以 @mephi42 建议我们添加对在 TinyCC 无法帮助我们的系统上使用 GCC 的支持。

我真的很喜欢这个主意。不仅从架构支持的角度来看，而且还因为可能获得更快的代码 —— TinyCC 针对小编译器足迹和快速编译进行了优化，而不是快速代码。

所以不用说，随着每一个朝着 GCC 支持的拉取请求，我都变得越来越兴奋。一旦最后一个落地，它就启发了我添加对在 i/macOS 上使用 Apple clang 的支持。

最后我们得到了这个：

{% highlight js %}
const cm = new CModule(`…`, {}, { toolchain: 'external' });
{% endhighlight %}

其中 `toolchain` 是 `any`, `internal`, 或 `external`。默认值为 `any`，这意味着如果 TinyCC 支持您的 `Process.arch`，我们将使用它，否则回退到 `external`。

不过，故事并没有到此结束。在实现对 i/macOS 的支持时，我并不清楚我们如何融合 JavaScript 端提供的符号。（CModule 构造函数的第二个参数。）

GCC 实现使用链接器脚本，这是一个 Apple 链接器不支持的非常优雅的解决方案。但这击中了我：我们已经有了用于注入器的自己的动态链接器。

一旦我把它连接起来，似乎真的很明显，我们也可以简单地支持完全跳过 Clang，并允许用户传入预编译的共享库。

当时的想法是，这将启用交叉编译，但也使得用 Swift 和 Rust 等语言实现 CModule 成为可能：基本上任何可以与 C 互操作的东西。

所以这意味着我们现在也支持以下内容：

{% highlight js %}
const cm = new CModule(blob);
{% endhighlight %}

其中 `blob` 是包含要从中构造它的共享库的 ArrayBuffer。目前这部分仅在 i/macOS 上实现，但目标是在所有平台上支持它。（欢迎贡献！）

此外，从 frida-tools 9.2 开始，REPL 的 `-C` 开关也支持这一点，使得使用外部工具链变得容易，而不会错过实时重新加载 —— 这使得开发期间的反馈循环更短。

更进一步，CModule API 现在还提供属性 `CModule.builtins`，脚手架工具可以使用它来获取内置头文件和预处理器定义。

关于这一点，我们现在在 frida-tools 中有这样一个工具：

{% highlight sh %}
$ mkdir pewpew
$ cd pewpew
$ frida-create cmodule
Created ./meson.build
Created ./pewpew.c
Created ./.gitignore
Created ./include/glib.h
Created ./include/gum/gumstalker.h
Created ./include/gum/gumprocess.h
Created ./include/gum/gummetalarray.h
Created ./include/gum/guminterceptor.h
Created ./include/gum/gumspinlock.h
Created ./include/gum/gummetalhash.h
Created ./include/gum/gummemory.h
Created ./include/gum/gumdefs.h
Created ./include/gum/gummodulemap.h
Created ./include/json-glib/json-glib.h
Created ./include/gum/arch-x86/gumx86writer.h
Created ./include/capstone.h
Created ./include/x86.h
Created ./include/platform.h

Run `meson build && ninja -C build` to build, then:
- Inject CModule using the REPL: frida Calculator -C ./build/pewpew.dylib
- Edit *.c, and build incrementally through `ninja -C build`
- REPL will live-reload whenever ./build/pewpew.dylib changes on disk

$ meson build && ninja -C build
…
[2/2] Linking target pewpew.dylib
$ frida Calculator -C ./build/pewpew.dylib
…
init()
[Local::Calculator]->
{% endhighlight %}

是的，它实时重新加载！做到极致，您可以使用文件监视工具并在 `pewpew.c` 更改时让它运行 `ninja -C build` —— 然后只需保存并立即看到检测在目标进程中生效。

值得注意的是，当使用内部 CModule 工具链时，您也可以使用上述内容，因为磁盘上有可用的头文件对于代码完成等编辑器功能很方便。

## EOF

还有很多其他令人兴奋的更改，所以一定要查看下面的变更日志。

享受吧！


### 14.2.0 中的变化

- 全新的 realms API，用于在 native 进程内检测模拟 realm。目前仅在 Android 上实现。
- 添加 Java.deoptimizeBootImage()。感谢 [@alkalinesec][]！
- 向 frida-server 添加 --disable-preload/-P。在操作系统兼容性问题的情况下很有用，其中 Frida 在附加到某些操作系统进程时会导致它们崩溃。
- 修复旧版本 Android 上的 libc 检测。
- 修复在 Android 上解析 vDSO 导出时的崩溃。感谢 [@ant9000][]！
- 恢复 Android 上对 libhoudini 的支持。
- 修复 Android 11 翻译器上的 ARM 缓存刷新。
- 修复 Android 5.x 的链接器偏移量。感谢 [@muhzii][]！
- 开始重构 CModule 的内部结构以准备多个后端。感谢 [@mephi42][]！
- 修复 ARM 上的 CModule 聚合初始化。
- 修复 ModuleApiResolver 快速路径发出错误匹配。

### 14.2.1 中的变化

- 修复 V8 运行时中的 CModule 构造函数错误路径。
- 在 Android 上为“system_server” agent 使用 V8 运行时。

### 14.2.2 中的变化

- 修复 Darwin.Mapper arm64e 处理没有修复的页面。这纯粹出于“运气”未被注意到，直到我们的二进制文件最终发生足够的变化以暴露此错误。

### 14.2.3 中的变化

- 升级到使用内联 hook 用于 ART 运行时。感谢 [@muhzii][]！
- 修复 i/macOS 上的直接传输回归，这是由 GLib 升级引入的，其中 GLib.Socket 在 Apple 操作系统上获得了 GLib.Credentials 支持。此回归的典型症状是 frida-server 被 Jetsam 杀死。
- 修复 32 位 Windows 上对 stdcall, thiscall, 和 fastcall 的 libffi 支持。
- 扩展 Memory.alloc() 以支持在给定地址附近分配。感谢 [@muhzii][]！
- 修复 x86_64 上 RIP 相对间接分支的重定位。感谢 [@dkw72n][]！
- 通过在放弃之前咨询调试符号来改进 JVM C++ 分配器 API 探测逻辑。感谢 [@Happyholic1203][]！
- 升级 SELinux 库以支持前沿 Android 系统。
- 添加 gum-linux-x86_64-gir 目标用于 GIR 生成。感谢 [@meme][]！

### 14.2.4 中的变化

- 修复使用 ART 解释器时的 Android 性能回归，例如在使用 deoptimizeEverything() 或 deoptimizeBootImage() 时，这会导致我们的 JS 回调变得非常热。将热回调移动到 CModule 以加快速度。
- 修复 Linux 上 Node.js 绑定中的 V8 调试器支持。
- 修复 libdwarf 后端中 ELF init 错误时的崩溃。

### 14.2.5 中的变化

- 修复 14.2.4 中引入的旧 Android 系统上的回归。

### 14.2.6 中的变化

- 修复与旧版 NativeBridge v3 及更高版本的兼容性，其中需要指定命名空间。

### 14.2.7 中的变化

- 修复在 printf() 渲染 %p 时没有“0x”前缀的系统上的 frida-java-bridge 崩溃。
- 修复 ARM64 上的 jni_ids_indirection_ 偏移量解析。感谢 [@muhzii][]！

### 14.2.8 中的变化

- 修复 i/macOS 上的 GLib SO_NOSIGPIPE 回归。这通常会导致 frida-server 由于 SIGPIPE 而死亡。感谢 [@mrmacete][]！
- 重构 CModule 内部结构并为 GCC 后端奠定基础。感谢 [@mephi42][]！
- 为只关心事件且不需要生命周期 hook 或代码转换的 Stalker C API 消费者添加 EventSink.make_from_callback()。
- 在块的开头发出 Stalker BLOCK 事件，因为这是最直观的，因为人们期望至少有与 COMPILE 事件一样多的 BLOCK 事件。此行为也最适合测量覆盖率。
- 添加 Stalker 预取支持，对于优化“AFL fork server”类用例很有用。

### 14.2.9 中的变化

- 处理 Darwin CodeSegment 后端中的永久条目。从 iOS 14.3 开始，在 A12+ 设备上，当目标 VM 映射条目标记为“永久”时，mach_vm_remap() 可能会返回 KERN_NO_SPACE。感谢 [@mrmacete][]！
- 在 CModule 中连接 GCC 支持。感谢 [@mephi42][]！
- 为 Apple 操作系统上的 Clang 添加 CModule 后端。
- 添加对链接预构建 CModule 的支持。（目前仅在 i/macOS 上。）
- 最终确定 CModule 工具链选择 API。
- 添加 CModule.builtins 属性以支持工具。
- 默认生成 frida-core GIR。感谢 [@meme][]！
- 修复 Linux/MIPS 上的回归。

### 14.2.10 中的变化

- 改进 frida-inject 以支持双向 stdio。
- 在 frida-python 中添加对 Termux 的支持：`pip install frida-tools` 现在可以工作了。

### 14.2.11 中的变化

- 改进 frida-inject 以支持原始终端模式。
- 为 Darwin 添加内部策略守护进程。
- 改进 Gum.Darwin.Mapper 以支持严格内核。

### 14.2.12 中的变化

- 修复 GC 后 ART 方法 hook 的可靠性。感谢 [@muhzii][]！

### 14.2.13 中的变化

- 修复 x86 上的 Instruction 操作数解析，确保立即数始终由 Int64 表示，而不是数字。感谢 [@muhzii][]！
- 修复进程未附加到终端时的 frida-inject。感谢 [@muhzii][]！
- 向 CModule 公开 Base64 和 Checksum GLib 原语。感谢 [@mrmacete][]！

### 14.2.14 中的变化

- 修复早期加载时 i/macOS 上的 Gadget 崩溃。
- 使 frida-inject stdin 通信可选。感谢 [@muhzii][]！
- 支持在 unc0ver 6.x 上 spawn iOS 应用程序。感谢 [@mrmacete][]！
- 解决 spawn iOS 应用程序时的单步延迟，以避免随机失败。感谢 [@mrmacete][]！
- 修复 libc shim 中的 read() 签名不匹配，这将导致在较新的 Apple 工具链上出现编译错误。感谢 [@Manouchehri][]！
- 修复较新版本 Android 上的 Android enumerate_applications() 名称截断。感谢 [@pancake][] 报告并帮助解决这个问题！
- 修复目标无法加载 frida-agent 时的挂起。
- 修复对附加到 Windows 服务的支持。
- 在注册新服务之前清理陈旧的 Windows 服务。
- 添加构建选项以支持使用已安装的资产而不是嵌入它们。
- 更新 iOS 打包以使用已安装的资产。
- 添加对受限 Android 的基本支持。感谢 [@enovella_][] 在这方面所有有趣和富有成效的结对编程！
- 扩展 Arm64Writer API 以支持更多立即数。
- 改进 Stalker 以支持 arm64 上暂时未对齐的堆栈。
- 修复 Stalker follow() 在没有 sink 时的崩溃。
- 实现 Stalker 失效支持。这允许更新检测而无需丢弃所有已翻译的代码。感谢 [@p1onk][] 在这方面的协助！
- 添加 Gum.DarwinModule.enumerate_function_starts()。
- 添加 Gum.DarwinGrafter 用于 AOT 嫁接，以便能够在无法进行运行时代码修改时准备二进制文件进行检测。感谢 [@mrmacete][] 的协助！
- 添加 Memory.allocate_near()。
- 提高所有支持架构上的 Stalker 性能和健壮性：
    - 改进调用探测以在目标处而不是调用站点进行探测，并利用新的失效基础设施。
    - 处理从调用探测中添加/删除调用探测。
    - 重构 callout 处理，以便可以在失效时销毁用户数据。这也消除了 callout 锁。
    - 在自修改代码的情况下，重新编译而不是分配新块。
    - 为代码和数据使用单独的 slab，以避免由于元数据存储空间不足而仅使用部分 slab 的情况。
    - 在 ExecCtx 中内联第一个代码/数据 slab，因此我们在跟踪不接触太多代码或根本不接触代码（如果它们没有唤醒）的线程时使用的内存要少得多。
    - 当 trust_threshold 为 0 时，不要费心存储原始代码。
    - 简化 Stalker 块元数据以减少每个块的内存消耗。
- 修复 ART 上 Java.enumerateMethods() 的结果。这是一个错误，其中静态初始化方法作为 '$init' 包含在枚举集中，而它们应该完全被跳过。感谢 [@muhzii][]！
- 修复 Java 方法 hook 期间使用的 Android/ART 近内存分配代码路径。感谢 [@muhzii][]！
- 修复泛型 Java 数组类型的处理。这允许稍后在编组数组类型时重用从运行时获得的数组对象，这对于保留类型信息是必要的，特别是在类型是动态的情况下。感谢 [@muhzii][]！
- 将 Android/ART StackVisitor 移植到 x86, x64, 和 ARM32。感谢 [@P-Sc][]！
- 修复 Android 上的 ARM 缓存刷新。事实证明 cacheflush() 在 Linux/ARM 上期望一个范围。这个 32 位 Android/ARM 回归是在 14.2.0 中引入的。
- 为 32 位 ARM 添加一些缺失的 TinyCC 内置函数。感谢 [@giantpune][] 报告并帮助解决这个问题！
- 修复 Stalker 块回收逻辑中的回绕。
- 修复从大数字构造 V8 NativePointer。
- 修复 Windows 上的 Stalker 本地线程操作。
- 修复 CModule 临时目录清理逻辑。
- 删除被遗忘的 InspectorServer 调试代码。
- 修复 V8 调试器集成。感谢 [@taviso][] 报告！

### 14.2.15 中的变化

- 修复与最新 unc0ver iOS 越狱的兼容性。感谢 [@mrmacete][]！
- 添加对 Anbox 的支持。感谢 [@asabil][]！
- 添加 Java.deoptimizeMethod()。感谢 [@liuyufei][]！
- 处理替换可能被去虚拟化的 ART 方法。感谢 [@liuyufei][]！

### 14.2.16 中的变化

- 为 32 位 ARM 添加许多缺失的 TinyCC 内置函数。感谢 [@giantpune][] 报告并帮助解决这个问题！
- 修复在 arm64 上使用 ADRP 时的 Android ART trampoline 对齐，以前在尝试替换某些方法时会导致抛出 `Error: invalid argument` 异常。感谢 [@pandasauce][] 报告并帮助解决这个问题！

### 14.2.17 中的变化

- 枚举来自链式修复的 Darwin 导入，以支持最新的 arm64e 二进制文件。感谢 [@mrmacete][]！
- 修复受限 iOS 注入器中的链式修复处理。感谢 [@mrmacete][]！
- qml: 使用 *no_keywords* 编译以实现 GLib 兼容性。感谢 [@suy][]！

### 14.2.18 中的变化

- 修复最近 XNU 版本上的 i/macOS 注入器，其中 mach_port_extract_right() 在尝试窃取目标进程的 POSIX 线程端口发送权限时失败并显示 KERN_INVALID_CAPABILITY。这导致注入器假设我们已经取消注入，随后释放仍在使用的内存。
- 修复受限 iOS 注入器中的 \_\_\_error 符号名称。感谢 [@mrmacete][]！
- 修复 Linux 后端中路径上带有空格的模块枚举。感谢 [@suy][]！
- 修复 x64 上直接分支地址的 Stalker 处理。
- python: 添加 RPC 导出列表功能。感谢 [@NewbieGoose][]！


[@alkalinesec]: https://twitter.com/alkalinesec
[Java bridge]: https://github.com/frida/frida-java-bridge
[@muhzii]: https://github.com/muhzii
[@mephi42]: https://github.com/mephi42
[@ant9000]: https://github.com/ant9000
[@dkw72n]: https://github.com/dkw72n
[@Happyholic1203]: https://github.com/Happyholic1203
[@meme]: https://github.com/meme
[@mrmacete]: https://twitter.com/bezjaje
[@Manouchehri]: https://github.com/Manouchehri
[@pancake]: https://twitter.com/trufae
[@enovella_]: https://twitter.com/enovella_
[@p1onk]: https://twitter.com/p1onk
[@P-Sc]: https://github.com/P-Sc
[@giantpune]: https://twitter.com/giantpune
[@taviso]: https://twitter.com/taviso
[@asabil]: https://twitter.com/asabil
[@liuyufei]: https://github.com/liuyufei
[@pandasauce]: https://github.com/pandasauce
[@suy]: https://github.com/suy
[@NewbieGoose]: https://github.com/NewbieGoose
