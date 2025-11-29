---
layout: news_item
title: 'Frida 12.1 发布'
date: 2018-08-25 23:00:00 +0200
author: oleavr
version: 12.1
categories: [release]
---

这次底层有大量变化。我们所有的依赖项都已升级到最新最好的版本。让我们看看亮点。

### V8 7.0

Frida 的 V8 依赖项以前是 6.2.2，现在已升级到 7.0.242。迁移到如此新的版本意味着 V8 调试器 API 已消失，并已被新的 Inspector API 取代，最新的 Node.js 也在使用它。关于它的一个非常棒的事情是它得到了 Google Chrome 的 Inspector 的原生支持。

要开始使用它，只需告诉 Frida 使用 V8，通过调用 *session.enable_jit()*，然后调用 *session.enable_debugger()*。

或者在使用 CLI 工具时：

{% highlight sh %}
$ frida-trace --enable-jit --debug -f /bin/cat -i read
{% endhighlight %}

然后在 Google Chrome 中，右键单击并选择"检查"，然后单击 Inspector 左上角的绿色 Node.js 图标。就是这样，您现在正在调试您的 Frida 脚本。这意味着一个带有自动完成的漂亮控制台、暂停/继续、单步执行、断点、分析和堆快照。使它真正方便的是服务器在您的主机上监听，因此您可以在表示 USB 系留的 Android 设备上的进程的会话上调用 *enable_debugger()*，它都以相同的方式工作。

这是它的样子：

![Console](/img/inspector-console.png "Console")
![Profiler](/img/inspector-profiler.png "Profiler")
![Heap Snapshot](/img/inspector-snapshot.png "Heap Snapshot")

但是请注意，V8 目前未包含在我们的预构建 iOS 二进制文件中，但现在应该可以在 iOS 上再次运行它，因为它能够在没有 RWX 页面的情况下运行。不过，我们确实计划在幕后桥接 Duktape 的二进制调试器协议，以便调试也可以与 Duktape "正常工作"，尽管可能功能集略有减少。

### Process.id

知道您的 agent 正在其中执行的进程的 PID 通常非常有用，尤其是在 [preloaded mode][] 中。因此，与其要求您使用 *NativeFunction* 来调用例如 *getpid()*，现在这要简单得多，因为您可以使用全新的 `Process.id` 属性。

### 还有别的吗？

没有其他功能，但有一些非常好的错误修复。感谢 [mrmacete][]，我们现在能够在 iOS 11.x 上附加到 *com.apple.WebKit.\\** 进程。感谢 [viniciusmarangoni][]，此版本还为 frida-java 打包了一些好东西，修复了一个 Android 8.0 回归并添加了正确检测 *system_server* 的能力。

享受吧！


[preloaded mode]: https://frida.re/docs/modes/#preloaded
[mrmacete]: https://github.com/mrmacete
[viniciusmarangoni]: https://github.com/viniciusmarangoni
