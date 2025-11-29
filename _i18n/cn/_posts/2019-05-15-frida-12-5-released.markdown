---
layout: news_item
title: 'Frida 12.5 发布'
date: 2019-05-15 23:00:00 +0200
author: oleavr
version: 12.5
categories: [release]
---

这是一个内容丰富的版本。有很多事情要谈。

### V8

这次的主要故事是 [V8][]。但首先，一点背景。

Frida 默认使用 [Duktape][] JavaScript 运行时来提供对其检测核心 [Gum][] 的可脚本化访问。我们最初只使用 V8，但由于 V8 过去依赖于对 *RWX* 页面的操作系统支持 —— 即也可写的可执行内存页面 —— 我们最终添加了基于 Duktape 的辅助 JS 运行时。由于 V8 的这种操作系统约束，以及 Duktape 缺乏对最新 JS 语法和功能的支持，我决定将 Duktape 作为我们的默认运行时，这样为一个平台编写的脚本就不需要任何语法更改就可以在另一个平台上工作。Duktape 基本上是最小公分母。

快进到今天，V8 不再依赖于对 *RWX* 页面的操作系统支持。它实际上正在朝着默认在 *RW-* 和 *R-X* 之间切换的方向发展。这样做意味着它可以在现代 iOS 越狱上使用，如果进程被标记为正在调试，也可以在受限 iOS 上使用，因此它能够运行未签名的代码。但还有更多；V8 现在甚至可以运行 [JIT-less][]，这意味着 Frida 可以在每个平台上使用 V8，用户不再需要 [frida-compile][] 他们的 agent 来使用最新的 JavaScript 语法和功能。不过，最后一点仅适用于简单的 agent，因为能够将非简单的 agent 拆分为多个源文件仍然是可取的。此外，frida-compile 使使用 [TypeScript][] 变得容易，这对于任何非简单的 Frida agent 都是强烈推荐的。

因此，考虑到所有这些，显然是时候将我们的 V8 升级到最新最好的版本了。从这个版本开始，我们正在运行 [7.6.48][]，并且我们与 V8 的集成比以往任何时候都更深入。C++ 内存分配和页级分配现在都由 Frida 管理，因此我们能够从 *Process.enumerateRanges()* 等 API 中隐藏这些内存范围，并避免用属于 Frida 的分配污染应用程序自己的堆。这些细节听起来可能并不那么重要，但实际上对于在 Frida 之上实现内存转储工具至关重要。然而，不仅如此，我们对正在观察的进程的干扰也更少。这意味着它表现出与没有检测时运行时不同行为的风险更小。

### 运行时选择

您可能还记得 *session.enable_jit()* API。它最终被弃用了，因为您现在可以在脚本创建期间指定所需的运行时。例如使用我们的 Python 绑定：

{% highlight python %}
script = session.create_script(source, runtime='duk')
{% endhighlight %}

使用我们的 Node.js 绑定：

{% highlight js %}
const script = await session.createScript(source, {
  runtime: 'v8'
});
{% endhighlight %}

### Stalker

此版本中的另一个重大变化是 [Stalker][] 在 arm64 上不再依赖于 *RWX* 页面，这要归功于 [John Coates][] 的出色贡献。这意味着 Stalker 终于在 iOS 上更容易访问了。

对于那些在 64 位 Windows 上使用 Stalker 并跟踪 32 位进程的人，它终于处理了较新版本 Windows 上的 WOW64 转换。这个令人费解的改进是由 [Florian Märkl][] 贡献的。

### Module.load()

有时您可能想要加载自己的共享库，可能包含用 C/C++ 编写的 hook。在大多数平台上，您可以通过使用 [NativeFunction][] 调用 *dlopen()*（POSIX）或 *LoadLibrary()*（Windows）来实现这一点。然而，在较新版本的 Android 上，情况却大不相同，因为它们的 *dlopen()* 实现会查看调用者并根据它做出决定。其中一个决定是应用程序是否试图访问私有系统 API，这会使他们以后很难删除或破坏该 API。因此，从 Android 8 开始，在这种情况下，实现将返回 *NULL*。这是 Frida 为其自己的注入器的需求解决的挑战，但想要加载自己库的用户基本上只能靠自己。

从 Frida 12.5 开始，有一个全新的 JavaScript API 可以为您处理所有平台特定的怪癖：

{% highlight js %}
const hooks = Module.load('/path/to/my-native-hooks.so');
Interceptor.replace(Module.getExportByName('libc.so', 'read'),
    hooks.getExportByName('replacement_read'));
{% endhighlight %}

### Android

我们在此版本中修复了许多 Android 特定的错误。例如，应用程序捆绑库上的 *Module.getExportByName()* 不再导致库在不同的基地址处第二次加载。仅此错误就足以确保您已升级所有设备并运行最新版本。

### iOS

iOS Chimera 越狱也得到了支持，这要归功于 [Francesco Tamagni][] 的出色贡献。

### 其余部分

跨平台还有许多其他改进。

按时间顺序：

- 子进程门控现在也可以在旧版本的 Windows 上工作。感谢 [Fernando Urbano][]！
- UNIX 操作系统上的可执行文件更小，因为它们不再导出任何动态符号。
- Frida 的 agent 和 gadget 在加载到高地址（即 MSB 已设置）时不再在 32 位 Linux 上崩溃。
- Linux/Android 的两个 *frida-helper-{32,64}* 二进制文件中只需要一个，对于没有跨架构支持的构建则不需要。这意味着更小的占用空间和更好的性能。
- Linux/ARM64 终于得到支持，二进制文件作为发布过程的一部分上传。
- 当我们的早期插桩无法在 Android 上检测 Zygote 时，我们现在提供有关 Magisk Hide 的提示。

### 12.5.1 中的变化

- 可以为每个脚本指定脚本运行时，弃用 *enable_jit()*。

### 12.5.2 中的变化

- Gadget 在 Linux 和 Android 上使用 V8 时在脚本加载时不再崩溃。非常感谢 [Leon Jacobs][] 报告并帮助追踪这个问题。

### 12.5.3 中的变化

- Android 链接器集成支持更多设备。
- Android Java 集成不再在某些 arm64 设备上因"无效指令"而崩溃。感谢 [Jake Van Dyke][] 报告并帮助追踪这个问题。
- 添加缺失的 SELinux 规则后支持 LineageOS 15.1。

### 12.5.4 中的变化

- Hook 不再能够干扰我们的 V8 页面分配器集成。
- 在我们的 libc shim 中堵塞一个漏洞后，Android 稳定性大大提高。非常感谢 [Giovanni Rocca][] 报告并帮助追踪这个问题！

### 12.5.5 中的变化

- Apple USB 设备在 Windows 上被正确检测。感谢 [@xiofee][]！

### 12.5.6 中的变化

- Android Java 集成现在对 ART 的异常传递逻辑中的一个错误有一个解决方法，其中一个特定的代码路径假设当前线程上至少存在一个 Java 堆栈帧。然而，在纯本机线程（如 Frida 的 JS 线程）上并非如此。最简单的重现器是 *Java.deoptimizeEverything()* 后跟不存在的类名的 *Java.use()*。感谢 [Jake Van Dyke][] 报告并帮助追踪这个问题。
- Android Java 集成在无法 TCP listen() 的进程中调用 *Java.deoptimizeEverything()* 时不再使进程崩溃。
- Android Java 集成像以前一样支持 JNI 检查模式。
- 除了 8 和 10 之外，还支持 Node.js 12，所有支持的平台都有预构建。
- Node.js 绑定的 *enableDebugger()* 方法不再需要指定要监听的端口。

### 12.5.7 中的变化

- Android 拆卸在我们无法为崩溃报告目的 spawn *logcat* 的系统上不再崩溃。
- Android 上更好的 *SuperSU* 集成拆卸逻辑。
- Android Java 集成现在正确支持 JNI 检查模式，这大大提高了 Android ROM 兼容性。感谢 [@muhzii][] 报告并协助测试更改。
- V8 后端拆卸不再遭受 use-after-free，并且在 WeakRef 绑定较晚时也不再崩溃。

### 12.5.8 中的变化

- Linux 子进程门控现在处理子进程更改架构，例如 32 位应用程序执行 fork+exec 以运行 64 位可执行文件。非常感谢 [@gebing][] 的修复。
- 在 fork+exec 的情况下，如果不跟踪子进程，子进程门控不再死锁。感谢 [@gebing][] 的修复。
- 模块导出查找不再在 Android 应用程序自己的模块上失败。

### 12.5.9 中的变化

- 我们的 libc shim 现在包括 *memcpy()*，使其可以安全地 hook。感谢 [Giovanni Rocca][] 调试并贡献修复。
- *Interceptor.flush()* 现在即使线程暂时释放了 JS 锁也可以工作，例如在调用 *NativeFunction* 时。
- Android Java 集成在 ART 异常传递期间不再间歇性崩溃，例如在 hook *ClassLoader.loadClass()* 时。感谢 [Jake Van Dyke][] 和 [Giovanni Rocca][] 帮助追踪这个问题。这个错误自从支持 ART 以来就一直存在，所以这个修复值得庆祝。🎉
- Android Java 集成不再使无法启动 *JDWP* 传输的进程崩溃。


[V8]: https://v8.dev/
[Duktape]: https://duktape.org/
[Gum]: https://github.com/frida/frida-gum
[JIT-less]: https://v8.dev/blog/jitless
[frida-compile]: https://github.com/oleavr/frida-agent-example
[TypeScript]: https://www.typescriptlang.org/
[7.6.48]: https://chromium.googlesource.com/v8/v8/+/refs/tags/7.6.48
[Stalker]: https://frida.re/docs/javascript-api/#stalker
[John Coates]: https://twitter.com/JohnCoatesDev
[Florian Märkl]: https://twitter.com/thestr4ng3r
[NativeFunction]: https://frida.re/docs/javascript-api/#nativefunction
[Francesco Tamagni]: https://twitter.com/bezjaje
[Fernando Urbano]: https://github.com/ineedblood
[Leon Jacobs]: https://twitter.com/leonjza
[Jake Van Dyke]: https://twitter.com/giantpune
[Giovanni Rocca]: https://twitter.com/iGio90
[@xiofee]: https://github.com/xiofee
[@muhzii]: https://github.com/muhzii
[@gebing]: https://github.com/gebing
