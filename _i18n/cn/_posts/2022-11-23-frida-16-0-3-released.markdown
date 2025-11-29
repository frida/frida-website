---
layout: news_item
title: 'Frida 16.0.3 发布'
date: 2022-11-23 12:02:32 +0100
author: oleavr
version: 16.0.3
categories: [release]
---

这次有一些很酷的新东西。让我们直接潜入。

## tvOS 和 watchOS

这次令人兴奋的贡献之一来自 [@tmm1][]，他打开了一大堆 pull-request，增加了对 tvOS 的支持。耶！作为落地这些的一部分，我借此机会也增加了对 watchOS 的支持。

这也证明是简化构建系统的好时机，摆脱了为支持非 Meson 构建系统（如 autotools）而引入的复杂性。因此，作为此清理的一部分，我们现在为模拟器目标（如 iOS 模拟器、tvOS 模拟器等）提供了单独的二进制文件。以前我们只支持 x86_64 iOS 模拟器，现在 arm64 也被覆盖了。

## macOS 13 和 iOS 16

本周早些时候，[@hsorbo][] 和我进行了一些有趣且富有成效的结对编程，我们解决了 Apple 最新操作系统中的动态链接器更改。那些在 i/macOS 上使用 Frida 的人可能已经注意到 spawn() 在 macOS 13 和 iOS 16 上停止工作。

这很有趣。事实证明，文件系统上的 dyld 二进制文件现在会在 [dyld_shared_cache][] 中查找与其自身具有相同 UUID 的 dyld，如果找到，则将执行向量到那里。解释为什么这破坏了 Frida 的 spawn() 功能需要一点背景知识，所以请忍受我一下。

当您调用 attach() 时，Frida 做的一部分工作是注入其代理（如果尚未这样做）。然而，在执行注入之前，我们会检查进程是否已充分初始化，即 libSystem 是否已初始化。

如果情况并非如此，例如在 spawn() 之后，目标在 dyld 的入口点暂停，Frida 基本上会推进主线程的执行，直到它到达 libSystem 准备就绪的点。这通常使用硬件断点来完成。

因此，因为新的 dyld 现在链接到 dyld_shared_cache 中的另一个副本，Frida 将断点放置在从文件系统映射的版本中，而不是缓存中的版本中。显然那从未被击中，所以我们在等待这种情况发生时最终会超时。

不过 [fix][] 相当简单，所以我们在最后一分钟设法将其挤进了发布中。

## 编译器改进

frida.Compiler 变得更好了，现在支持通过 tsconfig.json 进行额外配置，以及使用本地 frida-gum 类型定义。

## V8 调试器

V8 调试器集成因每个脚本拥有一个 V8 Isolate 的举措而被淘汰，这是 V8 快照支持所需的微妙重构。这现在已恢复正常工作。

## 依赖项升级

这次较重的提升之一显然是依赖项升级，我们的大多数依赖项现在都已升级：从支持 ARMv9.2 的 Capstone 到使用 PCRE2 的最新 GLib 等。

迁移到 PCRE2 意味着我们的 Memory.scan() 正则表达式支持刚刚升级，因为 GLib 以前使用的是 PCRE1。不过我们尚未在任何平台上启用 PCRE2 的 JIT，但这将是以后很容易改进的事情。

## 交叉发布: frida-tools 12.0.2

我们还有一个全新的 frida-tools 版本，感谢 [@tmm1][]，它具有一个令人兴奋的新功能。*frida-ls-devices* 工具现在显示更高保真度的设备名称，OS 名称和版本显示在第四列中：

![frida-ls-devices](/img/ls-devices-12-0-2.png "frida-ls-devices in 12.0.2"){: width="100%" }

要升级：

{% highlight bash %}
$ pip3 install -U frida frida-tools
{% endhighlight %}

## EOF

此版本中还有一些其他好东西，所以一定要查看下面的变更日志。

享受吧！

### 变更日志

- darwin: 添加对 watchOS 和 tvOS 的支持。感谢 [@tmm1][]！
- darwin: 修复 macOS 13 和 iOS 16 上的早期插桩。（感谢在此方面的结对编程，[@hsorbo][]！）
- interceptor: 在 W^X 系统（如 iOS）上改变页面时暂停线程。这提高了检测繁忙进程时的稳定性。
- system-session: 暂时重新启用 Exceptor。
- compiler: 允许配置 *target*, *lib* 和 *strict*。
- compiler: 修复对本地 frida-gum 类型定义的支持。
- compiler: 使用来自 git 的最新 *@types/frida-gum*。
- ci: 放弃 Node.js 10 的预构建。
- ci: 发布 Node.js 19 的预构建。
- ci: 发布 Electron 21 而不是 20 的预构建。
- unw-backtracer: 提高 32 位 ARM 上的准确性。
- thread: 向 Gum C API 添加 *suspend()* 和 *resume()*。
- darwin: 改进链式修复的处理。
- darwin: 修复 arm64e 上的 Objective-C 符号合成。
- linux: 检测 Linux 上的 *noxsave*。
- linux: 改进注入器以处理虚假的 .so 映射。感谢 [@lx866][]！
- module-map: 支持设置了 ptrauth 位的查找。
- gumjs: 添加 NativeFunction *traps: 'none'* 选项。感谢 [@mrmacete][]！
- gumjs: 防止 File 和 SQLite API 触发 Interceptor。感谢 [@mrmacete][]！
- gumjs: 在执行 V8 作业时持有 Isolate 锁。
- gumjs: 修复 V8 脚本拆卸时的死锁。
- gumjs: 修复 V8 调试器看不到加载的脚本。
- gumjs: 修复 Darwin/arm64e 上的 CModule 外部工具链支持。
- gumjs: 如果 V8 MAP_JIT 在 Darwin 上失败，则回退。
- gumjs: 初始化后不要冻结 V8 标志，以避免 Darwin 上强化进程的问题。
- socket: 升级到 libsoup 3.x 以支持 HTTP/2。
- devkit: 将 .gir 添加到 frida-core kit。感谢 [@lateralusd][]！
- devkit: 将示例更新为当前的 Device API。
- python: 在任何地方支持 UNIX 套接字地址。
- node: 修复 Node.js v19 兼容性。
- deps: 将大多数依赖项升级到最新最好的版本。
- build: 重构以摆脱非 Meson 的垃圾。


[@tmm1]: https://twitter.com/tmm1
[@hsorbo]: https://twitter.com/hsorbo
[dyld_shared_cache]: https://iphonedev.wiki/index.php/Dyld_shared_cache
[fix]: https://github.com/frida/frida-core/commit/73ac5eab9e6912bbd9903270e629e0d0ca773209
[@lx866]: https://github.com/lx866
[@mrmacete]: https://twitter.com/bezjaje
[@lateralusd]: https://github.com/lateralusd
