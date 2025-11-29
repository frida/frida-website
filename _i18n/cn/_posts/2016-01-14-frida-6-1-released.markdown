---
layout: news_item
title: 'Frida 6.1 发布'
date: 2016-01-14 19:00:00 +0100
author: oleavr
version: 6.1
categories: [release]
---

前段时间 [@s1341](https://github.com/s1341) 将 Frida 移植到了 QNX，就在几周前，他在嵌入式 ARM 设备上使用 Frida 时遇到了内存占用问题。这就在他贡献了将 Frida 移植到 linux-arm 的拉取请求之后。我们开始意识到可能是时候使用新的 JavaScript 运行时了，并同意 [Duktape](http://duktape.org/) 似乎非常适合我们的需求。

这个运行时现在已经落地，所有测试都通过了，它甚至在调用带有空 *onEnter*/*onLeave* 回调的 hook 函数的测量开销上击败了我们的 V8 运行时。给您一个概念：

{% highlight sh %}
…/interceptor_on_enter_performance: V8 min=2 max=31 avg=2 OK
…/interceptor_on_enter_performance: DUK min=1 max=2 avg=1 OK
{% endhighlight %}

（数字以微秒为单位，在运行 OS X 10.11.2 的 4 GHz i7 上测量。）

无论如何，即使那个比较并不完全公平，因为我们做了一些我们在 V8 运行时中尚未做的巧妙回收和写时复制技巧，这个新运行时已经相当令人印象深刻了。它还允许我们在非常微小的设备上运行，并且像 V8 这样咆哮的 JIT 驱动怪兽与纯解释器之间的性能差异对于大多数 Frida 用户来说可能并不重要。

因此，从这个版本开始，我们还在所有预构建的二进制文件中包含了这个全新的运行时，以便您可以试用它并告诉我们它对您的效果如何。它只增加了几百 KB 的占用空间，与 V8 每个架构切片增加的 6 MB 相比根本不算什么。请通过向 CLI 工具传递 `--disable-jit`，或者在第一次调用 `session.create_script()` 之前调用 `session.disable_jit()` 来试用它。

考虑到这个新运行时还解决了一些需要在我们的 JavaScriptCore 运行时中进行大量工作才能修复的问题，例如忽略来自后台线程的调用并避免毒害应用程序的堆，我们决定摆脱该运行时，并在 V8 目前无法运行的操作系统（如 iOS 9）上切换到这个基于 Duktape 的新运行时。我们在运行时进行功能检测，因此您仍然可以像以前一样在 iOS 8 上使用 V8 —— 除非您像刚才提到的那样显式 `--disable-jit`。

最后，这是更改的摘要：

6.1.0:

- core: 用基于 Duktape 构建的继任者替换 JavaScriptCore 运行时
- core: 添加 *disable_jit()* 以允许用户试用新的 Duktape 引擎
- core: 修复 Linux 上注入尚未调用/绑定 *pthread_create* 的进程时的崩溃
- core: 添加对 linux-armhf (e.g. Raspberry Pi) 的支持
- python: 向 Session 添加 *disable_jit()*
- node: 向 Session 添加 *disableJit()*
- CLI tools: 添加 *--disable-jit* 开关
- frida-repl: 升级到最新的 prompt-toolkit
- frida-trace: 修复尝试跟踪部分解析的导入时的崩溃
- frida-trace: 在生成的处理程序中坚持使用 ES5 以实现 Duktape 兼容性

6.1.1:

- core: 修复 Duktape 运行时中的同步逻辑和错误处理错误

6.1.2:

- core: 修复导致注入时崩溃的 Android 回归
- core: 修复 Python 3.x 构建回归
- clr: 向 Session 添加 *DisableJit()*

6.1.3:

- core: 赋予 iOS frida-helper 与 Preferences 应用程序相同的所有 entitlements，以便系统会话脚本可以读取和写入系统配置
- core: 更改以支持其中临时目录/文件的 AppContainer ACL
- node: 修复 pid 检查，以便它允许附加到系统会话

6.1.4:

- core: 为 iOS 上的控制台二进制文件实现 spawn()
- core: 改进对 hook 低级 OS API 的支持
- core: 修复阻止我们注入 frida-agent 依赖的库尚未加载的 Mac 进程的映射器问题
- core: 使 InvocationContext 也可用于替换的函数

6.1.5:

- core: 在 frida-load 生成的脚本中添加对生成器函数的支持
- frida-repl: 修复导致挂起的竞争条件
- frida-repl: 修复退出时的虚假错误消息

享受吧！
