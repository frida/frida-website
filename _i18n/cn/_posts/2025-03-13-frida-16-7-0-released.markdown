---
layout: news_item
title: 'Frida 16.7.0 发布'
date: 2025-03-13 19:09:52 +0100
author: oleavr
version: 16.7.0
categories: [release]
---

在插桩软件时，一个具有挑战性的方面是处理事物的动态性质，从线程启动和终止，到模块加载和卸载。

例如，如果您使用 Stalker 跟踪正在执行的线程，这在考虑插桩本身之前就提出了一些基本挑战。

## 哪些线程？

虽然您*可以*使用 Interceptor 在某处放置内联 hook，以便当线程执行某些有趣的操作时，您再使用 Stalker 跟踪其执行，但有时您宁愿调用 Process.enumerateThreads() 并跟踪您认为有趣的线程。

每个线程可能有一个您可以使用的 `name`，但如果没有，您通常只能选择更模糊的选项。您可能会查看 `context` 属性提供的 CPU 寄存器，或者将其传递给 Thread.backtrace() 以对其进行“指纹识别”，或者您可能会查看在特定操作期间哪些线程花费了最多的 CPU 时间。

但是，如果您能找出线程的入口点例程和参数呢？现在您可以了：

{% highlight sh %}
$ frida -p 163431
Local::PID::163431 ]-> Process.enumerateThreads()
[
    …
    {
        "id": 163560,
        "name": "SDLAudioP1",
        "state": "waiting",
        "context": { … },
        "entrypoint": {
            "parameter": "0x561210844900",
            "routine": "0x7fc7781237c0"
        }
    }
]
{% endhighlight %}

## 未来的线程

接下来是跟踪尚未启动的线程的挑战。到目前为止，这需要 hook 特定于操作系统的内部结构。对于跨平台代理来说，这是相当大的维护复杂性。

我很高兴地宣布，我们现在为此提供了一个 API：

{% highlight js %}
const observer = Process.attachThreadObserver({
  onAdded(thread) {
    …
  },
  onRemoved(thread) {
    …
  },
  onRenamed(thread, previousName) {
    …
  }
});
{% endhighlight %}

`onAdded` 回调会立即随所有现有线程一起调用，因此可以轻松管理初始状态与更新，而无需担心竞争条件。当随全新线程调用时，调用是从该新线程同步发生的。所以这是 Stalker.follow() 它的完美位置，这样你就不会错过早期执行的任何指令。

相反，`onRemoved` 回调告诉您线程何时即将终止。调用是从该线程同步发生的，因此您仍然有机会在该线程的上下文中执行一些最终代码。

最后但并非最不重要的一点是，`onRenamed` 回调告诉您线程的 `name` 何时刚刚更改，以及它的前一个名称（如果有），如果没有则为 `null`。

所有回调都是可选的，但必须至少提供一个。

然后，如果您稍后想停止观察，您需要做的就是：

{% highlight js %}
observer.detach();
{% endhighlight %}

## 未来的模块

就像线程来来去去一样，模块/共享库也是如此。您可能会尽早应用您的插桩，以免错过早期活动。但是您越早应用插桩，应用程序的其他部分尚未加载的可能性就越大。

虽然卸载实际上可能不会发生，或者是因为应用程序不这样做，或者是因为动态加载器不支持它，但这是您可能必须处理的另一个方面。

到目前为止，处理所有这些都需要 hook 特定于操作系统的内部结构，这就带来了维护此类跨平台代理代码的所有复杂性。

我很高兴地分享，我们现在也为此提供了一个 API：

{% highlight js %}
const observer = Process.attachModuleObserver({
  onAdded(module) {
    …
  },
  onRemoved(module) {
    …
  }
});
{% endhighlight %}

就像 Process.attachThreadObserver() 一样，`onAdded` 回调会立即随所有现有模块一起调用，因此可以轻松管理初始状态与更新，而无需担心竞争条件。当随全新模块调用时，调用会在该模块加载后立即同步发生，但在应用程序有机会使用它之前。这意味着这是应用插桩的好时机，例如使用 Interceptor。

相反，`onRemoved` 回调告诉您模块何时消失。

两个回调都是可选的，但必须至少提供一个。

然后，就像线程观察者 API 一样，如果您稍后想停止观察，您需要做的就是：

{% highlight js %}
observer.detach();
{% endhighlight %}

## 分析代码

Gum（Frida 核心的 C 库）中一个鲜为人知的功能是它的名为 gum-prof 的库。它为分析代码提供了一些轻量级的构建块。从这个版本开始，我们终于将它们暴露给了 JavaScript。

让我们从主要组件 Profiler API 开始。它是建立在 Interceptor 之上的一个简单的最坏情况分析器：

{% highlight js %}
const profiler = new Profiler();
const sampler = new BusyCycleSampler();
for (const e of Process.getModuleByName('app-core.so')
      .enumerateExports()
      .filter(e => e.type === 'function')) {
  profiler.instrument(e.address, sampler);
}
{% endhighlight %}

与以特定频率对调用堆栈进行采样的传统分析器不同，您可以决定您有兴趣分析的确切函数。这就是事情变得有趣的地方。

当这些函数中的任何一个被调用时，分析器会在进入时抓取一个样本，在返回时抓取另一个样本。然后它减去这两个值来计算调用的代价。如果结果值大于它之前为特定函数看到的值，则该值将成为其新的最坏情况。

每当发现新的最坏情况时，知道大部分时间/周期/等都花在特定函数上并不一定足够。例如，该函数可能仅在某些输入参数下很慢。

这是一种情况，您可以在调用 `instrument()` 时为特定函数传入 `describe()` 回调。您的回调应该从参数列表和/或其他状态捕获相关上下文，并返回描述刚刚发现的新最坏情况的字符串。

当您稍后决定调用 `generateReport()` 时，您会发现计算出的描述嵌入在每个最坏情况条目中。

## 采样器

正如您在我们刚刚接触的 Profiler 示例代码中可能已经注意到的那样，我们现在也有了“采样器”的概念。我们实际上有六种不同的实现。它们的共同点是它们实现了一个方法 `sample()`，该方法返回表示最新测量值的 bigint。它表示什么取决于特定的采样器，但对 Profiler 来说这并不重要，因为它只关心两点之间的变化量。

但是，这些采样器也旨在直接用于其他目的。

这些是全新的采样器：

-   `CycleSampler`: 测量 CPU 周期，例如在 x86 上使用 RDTSC 指令
-   `BusyCycleSampler`: 测量仅由当前线程花费的 CPU 周期，例如在 Windows 上使用 QueryThreadCycleTime()
-   `WallClockSampler`: 测量时间的流逝
-   `UserTimeSampler`: 测量特定线程在用户空间中花费的时间
-   `MallocCountSampler`: 计算调用 malloc()、calloc() 和 realloc() 的次数
-   `CallCountSampler`: 计算调用您选择的函数的次数

关于如何使用 `UserTimeSampler` 的一个很酷的例子是用线程 ID 构造它，这意味着它将测量该特定线程在用户空间中花费的时间。通过为每个线程构造一个这样的采样器，并从每个采样器收集一个样本，然后您可以以某种特定方式运行应用程序，例如确保它被馈送特定的网络数据包。然后您将从每个采样器收集第二个样本，减去前一个样本以计算变化量/增量。这告诉您哪个线程在用户空间中花费的时间最多，因此您知道您可能想要 Stalker.follow() 哪个线程来进行近距离研究。

## EOF

还有大量其他令人兴奋的更改，所以一定要查看下面的变更日志。

感谢 [@hsorbo][] 在线程和模块观察者功能的随机部分进行有趣且富有成效的结对编程！🙌 感谢 [@mrmacete][] 和 [@as0ler][] 帮助测试和消除错误 🥳

享受吧！

## 变更日志

- 引入 `Process.attachThreadObserver()` 和 `ThreadRegistry` 用于监控线程创建、终止和重命名。
- 引入 `Process.attachModuleObserver()` 和 `ModuleRegistry` 用于监控模块加载和卸载。
- gumjs: 将 Gum 的 Profiler 和 Sampler API 暴露给 JavaScript。
- gumjs: 添加 `NativePointer#writeVolatile()` API。感谢 [@DoranekoSystems][]！
- fruity: 修复 Linux `getifaddrs()` 逻辑中的崩溃，其中没有地址的接口未被正确处理。
- memory-access-monitor: 提供对线程 ID 和寄存器的访问。
- darwin: 修复拆卸期间的竞争性内存泄漏。
- linux: 避免注入期间出现虚假的 .so 范围。
- linux: 处理注入期间的兼容范围。
- server: 添加 --device 用于服务特定设备。
- compiler: 将 `@types/frida-gum` 升级到 18.8.0。


[@DoranekoSystems]: https://github.com/DoranekoSystems
[@hsorbo]: https://twitter.com/hsorbo
[@mrmacete]: https://twitter.com/mrmacete
[@as0ler]: https://github.com/as0ler
