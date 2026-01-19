---
layout: news_item
title: 'Frida 12.11 发布'
date: 2020-07-24 19:00:00 +0200
author: oleavr
version: 12.11
categories: [release]
---

为了期待 Apple 发布 macOS 11，Frida 12.11 来了！此版本带来了与 macOS 11 Beta 3 的完全兼容性。不仅如此，我们现在还支持 Apple silicon 上的 macOS。耶！

值得注意的是，我们并没有止步于 arm64，我们还支持 arm64e。这个 ABI 仍然是一个移动的目标，所以如果你有一个 Developer Transition Kit (DTK) 并想试用一下，你必须禁用 SIP，然后添加一个引导参数：

{% highlight bash %}
$ sudo nvram boot-args="-arm64e_preview_abi"
{% endhighlight %}

考虑到这种令人敬畏的平台融合，实际上我们可能已经支持越狱的 iOS 14。一旦公开越狱可用，我们就会知道。至少它应该不需要太多工作来支持。

因此，对于那些探索 DTK 的人，您可以像往常一样获取我们的 CLI 工具和 Python 绑定：

{% highlight bash %}
$ pip3 install frida-tools
{% endhighlight %}

顺便说一句，我们刚刚发布了 [CryptoShark 0.2.0][]，强烈建议您查看一下。唯一的警告是，我们目前仅提供 macOS/x86_64 的二进制文件，因此如果您想在 macOS/arm64 上尝试此操作，多亏了 Rosetta，您将能够运行它，但是附加到“本地系统”设备上的进程将不起作用。

不过解决方法很简单 —— 只需从我们的 [releases][] 中获取 frida-server 二进制文件并启动它，然后将 CryptoShark 指向“本地套接字”设备。如果您想在一个系统上运行 CryptoShark 并附加到另一个系统上的进程，您也可以使用本地 SSH 端口转发：

{% highlight bash %}
$ ssh -L 27042:127.0.0.1:27042 dtk
{% endhighlight %}

此版本中还有许多其他令人兴奋的更改，因此请务必查看下面的变更日志。

享受吧！


### 12.11.0 中的变化

- 添加对 macOS 11 和 Apple silicon 的支持。
- 在 Darwin 上守护 helper 进程。感谢 [@mrmacete][]！
- 在 Linux 上守护 helper 进程。
- 修复使用 usbmuxd 时不可靠的 iOS 设备处理。感谢 [@mrmacete][]！
- 修复 i/macOS frida-helper 提前死亡时的无限等待。
- 添加 Android spawn() “uid” 选项以指定用户 ID。感谢 [@sowdust][]！
- 添加对最新 checkra1n 越狱的支持。感谢 [@Hexploitable][] 的协助！
- 提高 Stalker ARM 稳定性。
- 堵塞 Interceptor arm64 后端错误路径中的泄漏。
- 修复没有 RWX 页面的系统上 memcpy() 附近的拦截。
- 修复 Darwin/arm64e 上 CpuContext 指针的编码。
- 始终剥离 Darwin/arm64 上的回溯项。
- 修复大端系统上的 Linux 架构检测。
- 修复 ARM BE8 上的 Capstone 字节序配置。

### 12.11.1 中的变化

- 处理使用不同 ptrauth 密钥的 i/macOS 目标。
- 修复大端系统上的 Linux CPU 类型检测。
- 修复 Linux/ARM-BE8 上的早期插桩。
- 修复注入到阻塞在 SIGTTIN 或 SIGTTOU 上的 Linux 进程的问题。

### 12.11.2 中的变化

- 修复 macOS 11/x86_64 上的 Stalker thread_exit 探测。
- 修复 macOS 11/x86_64 上的缓慢导出解析。
- 修复 CModule 对 ARM 上 Capstone 头文件的支持。
- 将 ArmWriter 添加到 ARM 的 CModule 运行时。
- qml: 添加对指定要使用的脚本运行时的支持。

### 12.11.3 中的变化

- 修复 V8 运行时中 ModuleMap.values() 的原型。
- qml: 将 DetachReason 枚举与当前 Frida API 同步。
- qml: 修复 Device 生命周期逻辑。

### 12.11.4 中的变化

- 修复 macOS 11 beta 3 上的注入器。放弃对旧 beta 的支持。
- 放弃因 macOS 11 beta 3 而变得多余的 helper hack。
- 修复 i/macOS 内省模块的处理。

### 12.11.5 中的变化

- 修复 macOS 11 和 iOS 14 上使用 dyld 现代代码路径的进程的 i/macOS 早期插桩。
- 通过使用 VMThread::execute() 安装新方法，使 JVM 方法拦截更安全，该方法会阻塞所有 Java 线程，并使拦截热方法更安全。感谢 [@0xraaz][]！
- 向 ARM Relocator 添加对 SUB 指令的支持。这意味着在 32 位 ARM 上使用 Interceptor 和 Stalker 时提高了可靠性。
- qml: 通过添加缺失的包含来修复使用 GCC 的构建。

### 12.11.6 中的变化

- 将 iOS 受限注入器移植到新的 arm64e ABI。这意味着 iOS 14 beta 3 现在在受限模式下完全受支持，即使在 A12+ 设备上也是如此。

### 12.11.7 中的变化

- 改进 Linux 和 QNX 上的 libc 检测。感谢 [@demantz][]！
- 修复 libdwarf 后端中符号大小的检查。这意味着 Linux 上更可靠的调试符号解析。
- 修复脆弱的 Android activity 启动逻辑。感谢 [@muhzii][]！
- 通过清除 *kAccFastInterpreterToInterpreterInvoke* 标志来提高 Android Java hook 的可靠性。感谢 [@deroko][]！
- 防止在 *$dispose()* 之后使用 Java 包装器，以使此类危险错误更容易检测。
- 改进 frida-qml 构建系统并添加对独立使用的支持。

### 12.11.8 中的变化

- 在 Apple silicon 上添加对 macOS 11 beta 4 的支持。

### 12.11.9 中的变化

- 添加对带有 Xcode 12 开发者磁盘映像的受限 iOS 的支持。

### 12.11.10 中的变化

- node: 堵塞 IOStream 的 WriteOperation 中的泄漏。感谢 [@mrmacete][]！
- qml: 添加对列出应用程序的支持。
- qml: 在每个模型上公开“count”属性。
- 修复“add sb, pc, r4”的 ARM 重定位。
- 修复“add ip, pc, #4, #12”的 ARM 重定位。
- 当 Rn 在 reglist 中时修复 LDMIA 的 ARM writer 支持。

### 12.11.11 中的变化

- 在 Android R 上添加对不透明 JNI ID 的支持，以支持可调试的应用程序。感谢 [@muhzii][]！
- qml: 添加对 spawn 进程的支持。
- qml: 修复在 Linux 上与 devkit 链接时缺失的库。
- qml: 修复 Linux 上的静态链接。
- qml: 优化启动以不等待 enumerate_devices()。

### 12.11.12 中的变化

- 在 i/macOS 上的早期插桩期间初始化 CoreFoundation。感谢 [@mrmacete][]！
- 在 Stalker 中支持 NULL EventSink。感谢 [@meme][]！
- node: 提供 v10 和 v11 的 Electron 预构建。下一个版本将放弃 v9 的预构建。
- qml: 添加 post(QJsonArray)。

### 12.11.13 中的变化

- 修复 Android 11/arm64 上的 ART 内部探测。感谢 [@enovella_][]！
- 暂时为 V8 构建不带压缩的 GumJS 运行时，因为我们需要改进 frida-compile 以使用最新版本的 [terser][]。

### 12.11.14 中的变化

- 现在 frida-compile 已升级到最新版本的 [terser][]，为 V8 构建带压缩的 GumJS 运行时。

### 12.11.15 中的变化

- 添加对 iOS 14.x 安全 DTX 的支持。感谢 [@mrmacete][]！
- 修复 Android 11 上的 Java.deoptimizeEverything()。感谢 [@Gh0u1L5][]！

### 12.11.16 中的变化

- 修复 Arm64Relocator.can_relocate() 中的 arm64e 支持。感谢 [@mrmacete][]！
- 向 Stalker.follow() 添加“onEvent”选项。这允许在本机代码中同步处理事件 —— 通常使用 CModule 实现。当想要实现自定义过滤和/或排队逻辑以提高性能，或牺牲性能以换取可靠的事件传递时很有用。
- 向 EventSink 公开 Stalker 的实时 CpuContext。这可以通过“onEvent”回调和 Gum C API 访问。
- 向 CModule 运行时添加 Spinlock。

### 12.11.17 中的变化

- 在受限 iOS 上通过 LLDB 杀死，以尽可能避免通过 ProcessControl 杀死。事实证明，我们以前的行为使 debugserver 处于不良状态，导致被杀死的应用程序有时会显示为已在运行，从而导致后续 spawn() 尝试的早期插桩失败。感谢 [@mrmacete][]！
- 通过让 instrumentation 字段检测优雅地失败来修复旧 Android API 级别上的 Java bridge 初始化。反正我们在旧 API 级别上不需要它。
- 稍微减少每个脚本的 Duktape 内存使用量。不需要保留脚本源代码字符串。

### 12.11.18 中的变化

- 在受限 iOS 上检测最前端应用程序时跳过应用程序扩展。有时应用程序扩展作为第一个匹配的进程返回，随后抛出“无法解析 bundle ID 的 bundle 路径”。感谢 [@mrmacete][]！
- 改进 x86/x86_64 的 Android ART 检测偏移量检测。感谢 [@Gh0u1L5][]！
- 修复 Android 7.1-8.1 上的 JDWP 初始化失败。感谢 [@Gh0u1L5][]！
- 修复 libdwarf 后端中的最近符号逻辑。
- 堵塞基于 Duktape 的运行时的参数解析逻辑中的泄漏，其中如果解析后续参数之一时发生错误，任何收集的内存范围数组都会泄漏。


[CryptoShark 0.2.0]: https://github.com/frida/cryptoshark/releases/tag/0.2.0
[releases]: https://github.com/frida/frida/releases
[@mrmacete]: https://twitter.com/bezjaje
[@sowdust]: https://github.com/sowdust
[@Hexploitable]: https://twitter.com/Hexploitable
[@0xraaz]: https://twitter.com/0xraaz
[@demantz]: https://github.com/demantz
[@muhzii]: https://github.com/muhzii
[@deroko]: https://github.com/deroko
[@meme]: https://github.com/meme
[@enovella_]: https://twitter.com/enovella_
[terser]: https://github.com/terser/terser
[@Gh0u1L5]: https://github.com/Gh0u1L5
