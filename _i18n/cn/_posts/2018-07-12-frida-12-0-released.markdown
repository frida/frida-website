---
layout: news_item
title: 'Frida 12.0 发布'
date: 2018-07-12 12:00:00 +0200
author: oleavr
version: 12.0
categories: [release]
---

正如你们中的一些人可能已经注意到的那样，可能有一本关于 Frida 的 [book][] 正在编写中。在 [NowSecure][] 的日常工作中，我花了大量时间作为 Frida API 的用户，因此我经常想起过去的设计决策，我后来后悔了。尽管我多年来确实解决了其中的大部分问题，但有些问题解决起来太痛苦了，我一直把它们放在后面。快进到今天，考虑到所有这些问题出版一本书的想法让我觉得是时候咬紧牙关了。

这就是为什么我很高兴地宣布 Frida 12。我们终于达到了 Frida 演变的一个点，我们的基础可以被认为足够稳定，可以写一本书了。

让我们看看这些变化。

### CLI 工具

过去引起一些混淆的一件事是我们的 Python 绑定还附带了一些 CLI 工具。Frida 是一个用于构建工具的工具包，尽管我们提供了一些示例工具，但是否要安装它们应该由您决定。

到目前为止，这意味着任何使用我们的 Python 绑定构建工具的人最终都会依赖于 *colorama*、*prompt-toolkit* 和 *pygments*，因为我们的 CLI 工具恰好依赖于这些。

好吧，现在这改变了。如果您执行：

{% highlight sh %}
$ pip install frida
{% endhighlight %}

您现在只会获得我们的 Python 绑定。仅此而已。这个包没有依赖项。

不过，CLI 工具对您可能仍然有用，因此要安装它们，请执行：

{% highlight sh %}
$ pip install frida-tools
{% endhighlight %}

### 绑定中的便利 API

当时看起来是个好主意的事情是让我们的语言绑定在 [Session][] 对象上提供一些便利 API。想法是，只需要枚举加载的模块和可能几个内存范围，然后读取或写入内存的简单用例，不必加载自己的 agent。因此，我们的 Python 和 Node.js 绑定都在幕后为您执行此操作。

那时与 agent 通信有点繁琐，因为 [rpc][] API 不存在，但即便如此，这也是一个糟糕的设计决策。[JS APIs][] 很多，并非所有 API 都可以在不引入新复杂性层的情况下公开。另一个方面是，每个语言绑定都必须复制这样的便利 API，或者我们必须添加绑定可以公开的核心 API。两者都是糟糕的选择，并通过模糊界限引起混淆，最终使 Frida 新手感到困惑。诚然，它确实使一些非常简单的用例（如内存转储工具）变得更容易，但对于其他所有人来说，它只是增加了膨胀和混乱。

这些 API 现在终于从我们的 Python 和 Node.js 绑定中消失了。其他绑定不受影响，因为它们没有实现任何此类便利 API。

### Node.js 绑定

自从我们的 Node.js 绑定编写以来已经过去了几年，从那时起 Node.js 已经发展了很多。它现在支持 ES6 类、*async* / *await*、箭头函数、*Proxy* 对象等。

仅 *Proxy* 支持就意味着我们可以简化 [rpc][] 用例，例如：

{% highlight js %}
const api = await script.getExports();
const result = await api.add(2, 5);
{% endhighlight %}

到只是：

{% highlight js %}
const result = await script.exports.add(2, 5);
{% endhighlight %}

你们中的一些人可能还更喜欢用 [TypeScript][] 编写应用程序，与老式 JavaScript 相比，这是一个很棒的生产力提升。您不仅可以获得类型检查，而且如果您使用像 [VS Code][] 这样的编辑器，您还可以获得类型感知重构和惊人的代码完成。

然而，为了使类型检查和编辑器功能真正发光，拥有项目依赖项的类型定义至关重要。如今这很少是一个问题，除了那些使用 Frida 的 Node.js 绑定的人。到目前为止，我们没有提供任何类型定义。这终于得到了解决。我决定用 TypeScript 重写它们，而不是用类型定义来增强我们的绑定。这意味着我们还利用了现代语言功能，如 ES6 类和 *async* / *await*。

我们本可以就此打住，但那些从 TypeScript 使用我们的 Node.js 绑定的人仍然会发现这有点令人沮丧：

{% highlight js %}
script.events.listen('message', (message, data) => {
});
{% endhighlight %}

在这里，编译器对 *Script* 对象上存在哪些事件一无所知，以及此特定事件的回调签名应该是什么。我们终于解决了这个问题。API 现在看起来像这样：

{% highlight js %}
script.message.connect((message, data) => {
});
{% endhighlight %}

瞧。您的编辑器甚至可以告诉您支持哪些事件，并为回调中的代码提供适当的类型检查。太棒了！

### Interceptor

过去引起一些混淆的是，从 *onEnter* 或 *onLeave* 访问 *this.context.pc* 会给您返回地址，而不是您放置 hook 的指令的地址。这终于得到了修复。此外，*this.context.sp* 现在指向 x86 上的返回地址，而不是第一个参数。*Stalker* 在使用调用探针时也是如此。

作为破坏我们的回溯器实现的这次重构的一部分，我还改进了我们在 Windows 上的默认回溯器。

### Tether？

您可能想知道为什么 `frida.get_usb_device()` 会给您一个 *type* 为 *'tether'* 的 *Device*。现在终于是 *'usb'* 了，正如您所期望的那样。因此，我们的语言绑定终于与我们的 [core API][] 一致了。

### 12.0.1 中的变化

- core: 修复 32 位 x86 上的参数访问
- core: 将 *Stalker* 更新到新的 *CpuContext* 语义
- python: 将正确的 README 发布到 PyPI
- python: 修复 Windows 构建系统

### 12.0.2 中的变化

- core: 升级到 Capstone 的 *next* 分支
- core: 修复 Windows 上的 DbgHelp 回溯器并更新到最新的 DbgHelp
- python: 修复长描述
- java: 修复 *java.lang.Class.getMethod()* 的 hook —— 感谢 [0x3430D][]！

### 12.0.3 中的变化

- core: 修复 Capstone 升级破坏的 iOS 构建系统

### 12.0.4 中的变化

- core: 修复早期插桩时的 i/macOS libc++ 初始化 —— 感谢 [mrmacete][]！
- core: 添加对带掩码的内存搜索的支持 —— 感谢 [mrmacete][]！
- core: 修复 *InvocationContext.get_return_address()*
- node: 修复从异步函数返回 RPC 对象时的崩溃

### 12.0.5 中的变化

- core: 修复由 Capstone 升级引起的 arm64 崩溃，其中测试和分支解码逻辑无法解码负偏移量 —— 感谢 [mrmacete][] 发现并修复这个问题！
- core: 修复 MIPS 回归和一个崩溃器 —— 感谢 [r0ck3tAKATrashPanda][]！

### 12.0.6 中的变化

- python: 改进 *spawn()* 以在 Python 2.x 上支持 unicode aux 选项
- java: 修复缺少缓存目录时的 *Java.registerClass()*
- java: 使临时文件命名可配置

### 12.0.7 中的变化

- core: 修复 iOS 11.3.1 到 11.4.1 上的早期插桩 —— 感谢 [mrmacete][]！

### 12.0.8 中的变化

- core: 修复使用自定义进程名称启动 Android 应用程序 —— 感谢 [giantpune][]！
- java: 修复 Android 8.0 上的 *ClassLinker* 字段偏移量检测

享受吧！


[NowSecure]: https://www.nowsecure.com/
[book]: https://twitter.com/fridadotre/status/950085837445836800
[Session]: https://gist.github.com/oleavr/e6af8791adbef8fbde06#file-frida-core-1-0-vapi-L201-L226
[rpc]: https://frida.re/docs/javascript-api/#rpc
[JS APIs]: https://frida.re/docs/javascript-api/
[TypeScript]: https://www.typescriptlang.org/
[VS Code]: https://code.visualstudio.com/
[core API]: https://gist.github.com/oleavr/e6af8791adbef8fbde06
[0x3430D]: https://github.com/0x3430D
[mrmacete]: https://github.com/mrmacete
[r0ck3tAKATrashPanda]: https://github.com/r0ck3tAKATrashPanda
[giantpune]: https://github.com/giantpune
