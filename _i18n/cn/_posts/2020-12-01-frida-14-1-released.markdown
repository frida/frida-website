---
layout: news_item
title: 'Frida 14.1 发布'
date: 2020-12-01 12:00:00 +0200
author: oleavr
version: 14.1
categories: [release]
---

这次有很多好东西！🎉 让我们深入了解一下。

## 依赖项

我们刚刚将所有依赖项升级到了最新最好的版本。这项工作的一部分包括翻新用于构建它们的构建系统位。

有了这些改进，我们最终将支持完全从源代码构建 Frida 的旧版本，这是一个长期存在的问题，引起了很多挫折。

现在调整我们的依赖项也变得容易得多，例如在调试问题时。假设您正在排查为什么 *Thread.backtrace()* 在 Android 上工作不正常，您可能想要摆弄 libunwind 的内部结构。现在构建一个特定的依赖项真的很容易：

{% highlight bash %}
$ make -f Makefile.sdk.mk FRIDA_HOST=android-arm64 libunwind
{% endhighlight %}

或者，如果您正在为本地系统构建它：

{% highlight bash %}
$ make -f Makefile.sdk.mk libunwind
{% endhighlight %}

但是您可能已经构建了 Frida，并希望在其使用的预构建 SDK 中换出 libunwind。要做到这一点，您现在可以执行：

{% highlight bash %}
$ make -f Makefile.sdk.mk symlinks-libunwind
{% endhighlight %}

然后，您可以继续更改“deps/libunwind”，并通过重新运行以下命令执行增量编译：

{% highlight bash %}
$ make -f Makefile.sdk.mk libunwind
{% endhighlight %}

## iOS

我们现在支持 iOS 14.2。它其实已经可以工作了，但是我们的崩溃报告器集成会死锁 Apple 的崩溃报告器，这对于整体系统稳定性来说并不好。

## GumJS 支持 size_t 和 ssize_t

感谢 [@mame82][]，我们终于在 *NativeFunction* 等 API 中支持“size_t”和“ssize_t”。这意味着您的跨平台 agent 不再需要维护与这些对应的本机类型的映射。耶！

## 系统 GLib 支持

[Gum][] 终于可以使用上游版本的 GLib 构建，我们现在支持生成 [GObject introspection][] 定义。这为未来完全自动生成的语言绑定铺平了道路。

感谢 [@meme][] 带来的这些很棒的改进！

## Windows 进程内注入

我们的 Windows 后端终于支持进程内注入。我的意思是，在目标进程架构相同且不需要提升权限的最常见情况下，我们现在可以避免将“frida-helper-{32,64}.exe”写出到临时目录并在我们能够 *attach()* 到给定目标之前启动它。作为额外的奖励，这也减少了我们的启动时间。

这项改进背后的动机是修复一个长期存在的问题，即某些端点安全产品会阻止我们的注入器工作，因为我们的逻辑很容易在此类软件中触发误报。当我们确实需要 spawn 我们的 helper 时，我们显然仍然会遇到此类问题，但现在很有可能最常见的用例实际上可以工作。

## Stalker ARM 改进

对于那些在 32 位 ARM 上使用 Stalker 的人来说，它现在应该比以往任何时候都工作得更好。此版本中包含了大量的修复。

## 字节码和 frida-tools

自 14.0 发布以来的一个认识是，QuickJS 的字节码格式比预期的要不稳定得多。因此，我建议不要使用“frida-compile -b”，除非您的应用程序设计为仅与一个确切版本的 Frida 一起使用。

由于我在发布上一版 frida-tools 时没有意识到这个陷阱，我选择将 frida-trace agent 预编译为字节码。在致力于发布 14.1 时意识到我的错误后，我撤销了这个错误并发布了新版本的 frida-tools。

因此，请确保在升级时也获取其最新版本：

{% highlight bash %}
$ pip3 install -U frida-tools
{% endhighlight %}

## EOF

还有很多其他令人兴奋的更改，所以一定要查看下面的变更日志。

享受吧！


### 14.1.0 中的变化

- 所有依赖项升级到最新最好的版本。
- 严重翻新的依赖项构建系统。展望未来，我们将最终支持完全从源代码构建 Frida 的旧版本。
- 将 iOS 崩溃报告器集成移植到 iOS 14.2。
- 修复与 iOS 设备对话时的错误传播。
- 在 GumJS 中添加对“size_t”和“ssize_t”的支持。感谢 [@mame82][]！
- 支持链接系统 GLib 和 libffi。感谢 [@meme][]！
- 支持 GObject Introspection。感谢 [@meme][]！
- 改进 Windows 后端以支持进程内注入。这意味着我们可以避开常见的 AV 启发式方法，并在目标进程架构相同且不需要提升权限的最常见情况下加快速度。
- 修复 Stalker ARM 对“ldr pc, [sp], #4”的处理。
- 修复 Stalker ARM 对 IT 块中标志的破坏。
- 修复 Stalker ARM 对 IT 块中 CMN/CMP/TST 的处理。
- 修复 ThumbWriter 指令的抑制标志。
- 修复 Stalker ARM 排除逻辑的可靠性。
- 修复 ARM Stalker 在 Thumb 模式下 follow() 线程的问题。
- 修复 Thumb 模式下的 ARM Stalker SVC 处理。
- 修复 ThumbRelocator 对未对齐 ADR 的处理。
- 将 Stalker ARM 移动到运行时 VFP 功能检测。
- 拒绝没有任何回调的 Interceptor.attach()。
- 改进 GumJS 错误消息格式。
- 修复 V8 调试器集成中的饥饿问题。
- 在 V8 上调用期间也保持 NativeCallback 存活。

### 14.1.1 中的变化

- 修复 Capstone 丢失的 CModule 回归。
- 为 32 位 ARM 添加缺失的 CModule 内置函数。
- 修复 Android/ARM64 上的 Thread.backtrace()。

### 14.1.2 中的变化

- 修复 Android/ARM 上的 Thread.backtrace()。

### 14.1.3 中的变化

- 修复 ObjC.choose()。14.1.0 中的 TinyCC 升级暴露了一个现有错误。
- 默认重新启用 V8。事实证明，我们有用例比 QuickJS 更适合它，并且它的调试器功能也被严重怀念。
- 向 frida-server 添加 --ignore-crashes/-C 以禁用本机崩溃报告器集成。适用于不希望集成的情况，或者在运行我们尚未完全支持的前沿操作系统版本时。（崩溃报告器集成目前仅在 iOS 和 Android 上可用。）
- 增强 devkits 以确保 Capstone API 在所有平台上都公开。
- 改进 devkit 示例。


[@mame82]: https://twitter.com/mame82
[Gum]: https://github.com/frida/frida-gum
[GObject introspection]: https://gi.readthedocs.io/en/latest/
[@meme]: https://github.com/meme
