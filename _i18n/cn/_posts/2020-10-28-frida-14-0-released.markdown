---
layout: news_item
title: 'Frida 14.0 发布'
date: 2020-10-28 05:55:00 +0200
author: oleavr
version: 14.0
categories: [release]
---

这是一个重要的新版本，经历了数周的紧张编码，喝了太多的咖啡。但在我们深入研究之前，我们需要快速回顾一下过去。

多年来，我们基于 V8 的运行时一直为我们服务得很好。但最终我们需要支持 V8 不太适合的受限系统，所以我们引入了第二个运行时。

这效果很好，但我们留下了一些权衡：

- 两个运行时之间的语言功能支持差异很大。我们试图通过将简约运行时设为默认来缓解这种情况，因为它随处可用，并且在功能方面是最小公分母。
- 使用 [frida-compile][] 等工具将现代 JavaScript 编译为在两个运行时上运行的旧 JavaScript 时，需要牺牲性能。
- 具有大量代码和数据浮动的非平凡 agent 清楚地表明，不仅 V8 很快 —— 这不足为奇 —— 而且它非常擅长打包对象以避免浪费宝贵的 RAM。为了进一步扩大两个运行时之间的差距，V8 可以按原样运行现代 JavaScript，不需要运行包含兼容性垫片以填充缺失的运行时位（如 *Map* 和 *Set*）的臃肿版本。
- 示例代码和文档往往看起来很晦涩，以避免混淆可能尝试在默认运行时上运行现代代码的用户。
- 垃圾收集器实现的差异可能会隐藏用户在一个运行时中的错误，而在另一个资源释放得更急切的运行时中立即爆炸。一个这样的例子是在外部代码仍在使用 NativeCallback 时未能保持其存活。
- 糟糕的用户体验：所有这些对我们的用户来说都是一个非常令人沮丧和困惑的故事。
- 新功能和改进需要实现两次。出于显而易见的原因，这对我作为维护者来说真的很痛苦。

快进到 2019 年，[QuickJS][] 引起了我的注意。不过，当时我真的很忙于其他事情，所以当我仔细观察它时，我注意到它支持 ES2020，并且对于解释器来说 [performs][] 令人印象深刻。

但是，当我开始考虑从头开始建立一个新的运行时，并且看到其他两个大约各为 ~25 KLOC 时，这感觉太让人不知所措了。

不过，我一直回到 QuickJS 网站，如饥似渴地阅读技术细节，甚至在某个时候开始更深入地阅读公共 API。

然后我注意到它不支持协作多线程使用，即多个线程步调一致地执行 JavaScript。这使得面前的工作山感觉更加令人生畏，但后来我记得我已经为 Duktape 贡献了对此的支持，而且并没有那么难。

最终我鼓起勇气。从 GumJS 广泛的 [test-suite][] 中挑选了一个超级简单的测试作为我的第一个挑战，然后继续复制粘贴现有的两个运行时中最年轻的一个的 [ScriptBackend][] 和 [Script][] 实现。首先重命名事物，然后存根所有模块（Interceptor, Stalker 等），只是想得到一个近乎空的“shell”来编译和运行。

此时我上钩了，停不下来。消耗了大量的咖啡，在我知道之前，我已经实现了核心位和第一个模块。然后是另一个，再一个。

在使用 QuickJS API 进行了相当多的工作，并在其内部跳来跳去以确保我理解引用计数规则等之后，突然真的很清楚需要什么来实现协作多线程 API，这将是使其成为真正的运行时而不仅仅是玩具所必需的。

我们需要能够做的是在调用 NativeFunction 时暂停 JS 执行。这是因为被调用的函数可能会阻塞等待另一个线程可能已经持有的锁，但另一个线程可能刚刚调用了一个 hook 函数并正在等待进入 JS 运行时。因此，如果我们在调用 NativeFunction 之前不释放 JS 锁，我们现在就会陷入死锁。

另一个用例是调用 *Thread.sleep()* 或其他一些阻塞 API，如果我们持有 JS 锁时这样做，会导致饥饿。

无论如何，[QuickJS multi-threading API][] 证明是直截了当的，所以从那里我继续前进，直到一切最终 [done][]！🎉

此时我真的很好奇这个全新运行时的性能，首先是进入和离开它的成本问题。

继续在 iPhone 6 上试用它，运行 GumJS [test][]，该测试使用 Interceptor hook 一个几乎为空的 C 函数，提供一个空的 JS 回调，然后测量每次调用所花费的挂钟时间，因为它不断地一遍又一遍地调用 C 函数。

这个想法是模拟如果用户 hook 一个频繁调用的函数会发生什么，以了解基本开销。

这是我得到的：

{% highlight bash %}
# QuickJS
<min: 1.0 us, max: 7.0 us, median: 2.0 us> ok 1 /GumJS/Script/Interceptor/Performance/interceptor_on_enter_performance#QJS
<min: 2.0 us, max: 54.0 us, median: 2.0 us> ok 2 /GumJS/Script/Interceptor/Performance/interceptor_on_leave_performance#QJS
<min: 3.0 us, max: 18.0 us, median: 3.0 us> ok 3 /GumJS/Script/Interceptor/Performance/interceptor_on_enter_and_leave_performance#QJS
# Duktape
<min: 2.0 us, max: 8.0 us, median: 3.0 us> ok 4 /GumJS/Script/Interceptor/Performance/interceptor_on_enter_performance#DUK
<min: 2.0 us, max: 6.0 us, median: 3.0 us> ok 5 /GumJS/Script/Interceptor/Performance/interceptor_on_leave_performance#DUK
<min: 4.0 us, max: 89.0 us, median: 4.0 us> ok 6 /GumJS/Script/Interceptor/Performance/interceptor_on_enter_and_leave_performance#DUK
# V8
<min: 13.0 us, max: 119.0 us, median: 14.0 us> ok 7 /GumJS/Script/Interceptor/Performance/interceptor_on_enter_performance#V8
<min: 15.0 us, max: 127.0 us, median: 16.0 us> ok 8 /GumJS/Script/Interceptor/Performance/interceptor_on_leave_performance#V8
<min: 26.0 us, max: 198.0 us, median: 28.0 us> ok 9 /GumJS/Script/Interceptor/Performance/interceptor_on_enter_and_leave_performance#V8
{% endhighlight %}

哇，这看起来很有希望！[baseline memory usage][] 怎么样，即运行时本身的一个实例消耗多少内存？

![QJS Memory Baseline](/img/qjs-memory-baseline.png "QJS Memory Baseline")

这是一个相当大的改进 —— 只有以前运行时的五分之一！

我好奇的下一件事是使用我们的 REPL 时 Frida 内部堆的大致初始大小。这包括 frida-agent、JS 运行时和加载的 REPL agent 使用的所有内存：

![QJS Memory REPL](/img/qjs-memory-repl.png "QJS Memory REPL")

耶，释放了 1 MB 用于其他目的！

因此，我希望您像我一样对这个新版本感到兴奋。我们已经用这个基于 QuickJS 构建的全新运行时替换了我们以前的默认运行时。

作为一个实验，我也决定在没有 V8 运行时的情况下构建我们的官方二进制文件。这意味着二进制文件比以往任何时候都小得多。

我确实意识到你们中的一些人可能有 V8 运行时必不可少的用例，所以我希望你们能试用新的 QuickJS 运行时，并让我知道它对你们的效果如何。如果对于您的特定用例来说这绝对是一场灾难，请不要担心，只需告诉我，我们会想办法解决。

如果您想在启用 V8 运行时的情况下自己构建 Frida，只需调整 [this line][] 即可。但是，如果您离不开它，请务必告诉我，以便我们可以决定以后是否需要继续支持此运行时。

此主要版本中唯一的另一个更改适用于 i/macOS，我们终于跟随 Apple 的举措放弃了对 32 位程序的支持。不过我们暂时会保留代码路径，但我们的官方二进制文件脂肪少得多，顶级构建系统也稍微苗条一些。例如 `make core-macos-thin` 现在只是 `make core-macos`。

这就是 Frida 本身的所有内容，但还有更多。我们也发布了 frida-tools 9.0，刚刚升级以随处使用现代 JavaScript 功能。这包括 frida-trace，其中生成的样板 hook 在一些语法升级后变得更具可读性。最后但并非最不重要的一点是，我们也发布了 frida-compile 10.0，其中 Babel 依赖项消失了，相应的命令行开关也消失了；它更快，也简单得多。

因此，希望您会喜欢这个新版本！

### 14.0.0 中的变化

- 将默认运行时替换为基于 QuickJS 的全新 GumJS 运行时。
- 默认禁用 V8。
- 在 V8 上保留 Interceptor.attach() 中的回调对象。
- 从全局访问 API 中删除“enumerate”陷阱。

### 14.0.1 中的变化

- QJS: 修复嵌套的全局访问请求。
- qml: 更新到新的 frida-core API。

### 14.0.2 中的变化

- QJS: 在调用期间保持 NativeCallback 存活。
- QJS: 加速 NativeCallback 构造逻辑。
- QJS: 暂时禁用堆栈限制。
- iOS: 将 iOS 崩溃报告器集成移植到 iOS 14。
- iOS: 删除 32 位的打包逻辑。
- Android: 为“system_server” agent 使用默认运行时。
- 现代化内部 JavaScript agent。

### 14.0.3 中的变化

- 在 Windows 上也禁用 V8。
- iOS: 改进打包脚本。

### 14.0.4 中的变化

- iOS: 修复由工具链升级引起的 arm64e 回归。

### 14.0.5 中的变化

- QJS: 修复 Interceptor 错误处理。

### 14.0.6 中的变化

- ObjC: 修复替换方法的生命周期，使它们不绑定到类包装器，并且在链接用例中也保持存活。感谢 [@Hexploitable][] 和 [@mrmacete][] 的协助！
- 修复当 act == oact 时 Exceptor sigaction() 注册失败。感谢 [@hluwa][]！
- 改进 Linux libc 检测。
- 修复在 Linux 上枚举和修改线程时间歇性挂起。
- 修复不一致的 PC vs CPSR Thumb 位处理。
- 修复 Linux/armhf 和 Linux/arm64 上的构建回归。
- 发布 Raspberry Pi 32 位和 64 位二进制文件。

### 14.0.7 中的变化

- 避免在执行 JS 代码时崩溃的场景中死锁，例如在调用带有 `exceptions: 'propagate'` 的 NativeFunction 时，或者在 GumJS 中存在错误的情况下。感谢 [@mrmacete][]！
- 修复 macOS/arm64 上的 CModule。
- 发布 Raspberry Pi 32 位的 Python 和 Node.js 二进制文件。
- 发布 Fedora 33 而不是 Fedora 32 的二进制文件。
- 发布 Ubuntu 20.10 的二进制文件。

### 14.0.8 中的变化

- 通过在上传连接中添加一些双向通信来提高受限 iOS 上传的可靠性。这是为了防止在复杂的远程配置中的 gadget 上传期间启动 DoS 保护。感谢 [@mrmacete][]！


[frida-compile]: https://github.com/frida/frida-compile
[QuickJS]: https://bellard.org/quickjs/
[performs]: https://bellard.org/quickjs/bench.html
[test-suite]: https://github.com/frida/frida-gum/blob/6873f1504e40ad1a8bbc51d469c95519a2076fb0/tests/gumjs/script.c
[ScriptBackend]: https://github.com/frida/frida-gum/blob/6873f1504e40ad1a8bbc51d469c95519a2076fb0/bindings/gumjs/gumscriptbackend.h
[Script]: https://github.com/frida/frida-gum/blob/6873f1504e40ad1a8bbc51d469c95519a2076fb0/bindings/gumjs/gumscript.h
[QuickJS multi-threading API]: https://github.com/frida/quickjs/commit/7ec1392b19bcf6ae2b109cda3e2133c5d6918a6c
[done]: https://github.com/frida/frida-gum/commit/c47c0711c72a87e729e3e59110b7f611ff392fe2
[test]: https://github.com/frida/frida-gum/blob/6873f1504e40ad1a8bbc51d469c95519a2076fb0/tests/gumjs/script.c#L5089-L5137
[baseline memory usage]: https://github.com/frida/frida-gum/blob/6873f1504e40ad1a8bbc51d469c95519a2076fb0/tests/gumjs/script.c#L7356-L7399
[this line]: https://github.com/frida/frida/blob/b5aa3aa623c2d919e7fe7c34eee9ded31da8212e/config.mk#L22
[@Hexploitable]: https://twitter.com/Hexploitable
[@mrmacete]: https://twitter.com/bezjaje
[@hluwa]: https://github.com/hluwa
