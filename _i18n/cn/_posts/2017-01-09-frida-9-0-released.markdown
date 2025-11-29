---
layout: news_item
title: 'Frida 9.0 发布'
date: 2017-01-09 01:00:00 +0200
author: oleavr
version: 9.0
categories: [release]
---

这次有一些重大变化。我们现在默认在所有平台上使用基于 [Duktape][] 的 JavaScript 运行时，iOS 应用程序启动不再搭载 Cydia Substrate，并且我们带来了一些巨大的性能改进。还有一些错误修复。

先说说 Duktape。Frida 的第一个 JS 运行时基于 [V8][]，我对这个选择非常满意。然而很明显，有些用例并不适合它。

有些系统，例如 iOS，不允许 RWX 内存<sup id="ios-rwx-sup">[1](#ios-rwx)</sup>，而 V8 没有它就无法运行。另一个例子是资源受限的嵌入式系统，那里根本没有足够的内存。而且，正如用户不时报告的那样，有些进程决定将其线程配置为具有微小的堆栈。然而 V8 非常消耗堆栈，所以如果您 hook 任何这些线程调用的函数，它不一定能够进入 V8，您的 hook 似乎被忽略了<sup id="v8-stack-sup">[2](#v8-stack)</sup>。

另一个方面是，对于本机 ⇔ JS 转换，V8 比 Duktape 昂贵得多，所以如果您的 Frida agent 全是关于 API hook，并且您的 hook 非常小，那么使用 Duktape 实际上可能会更好。Duktape 的垃圾收集也更可预测，这对于 hook 时间敏感代码很有好处。

也就是说，如果您的 agent 大量使用 JavaScript，V8 会快得多。它还带有本机 ES6 支持，尽管这并不是什么大问题，因为非简单的 agent 应该使用 [frida-compile][]，它将您的代码编译为 ES5。

所以 V8 运行时不会消失，它将仍然是一等公民。唯一改变的是我们默认选择 Duktape，这样您就可以保证在所有平台上获得相同的运行时，并且很有可能会工作。

但是，如果您的用例大量使用 JS，您所要做的就是在创建第一个脚本之前调用 *Session#enable_jit()*，就会使用 V8。对于我们的 CLI 工具，您可以传递 *--enable-jit* 来获得相同的效果。

那是 Duktape。那么关于应用程序启动和 Substrate 的故事是什么？好吧，到目前为止，我们的 iOS 应用程序启动一直搭载在 Substrate 上。这是一个务实的解决方案，为了避免进入互操作性场景，其中 Frida 和 Substrate 都会 hook launchd 和 xpcproxy 中的 *posix_spawn()*，并互相踩踏。

然而，修复这个问题一直在我长期的待办事项清单上，因为它在其他领域增加了许多复杂性。例如，带外回调机制，以便我们的 Substrate 插件可以在加载时与我们对话，必须管理临时文件等。除此之外，这意味着我们依赖于闭源第三方组件，即使它是仅 iOS 应用程序启动所需的软依赖项。但是，它仍然是 Frida 唯一间接需要对运行系统进行永久修改的部分，我们真的想避免这种情况。

让我们看看新的应用程序启动是如何工作的。想象一下，您在连接了越狱 iOS 设备的主机上运行此命令：

{% highlight bash %}
$ frida-trace -U -f com.atebits.Tweetie2 -i open
{% endhighlight %}

我们告诉它启动 Twitter 的 iOS 应用程序并跟踪名为 *open* 的函数。顺便说一句，如果您对细节感到好奇，frida-trace 是用 Python 编写的，只有不到 900 行 [code][]，所以这可能是了解更多关于在 Frida 之上构建自己的工具的好方法。或者也许您想改进 frida-trace？更好！

它做的第一部分是获取第一个 USB 设备并在那里启动 Twitter 应用程序。这归结为：

{% highlight py %}
import frida

device = frida.get_usb_device()
pid = device.spawn(["com.atebits.Tweetie2"])
{% endhighlight %}

现在幕后发生的事情是这样的：

1. 我们将 [launchd.js][] agent 注入 launchd（如果尚未完成）。
2. 调用 agent 的 RPC 导出的 [prepareForLaunch()][]，给它我们要启动的应用程序的标识符。
3. 调用 [SBSLaunchApplicationWithIdentifierAndLaunchOptions()][] 以便 SpringBoard 启动应用程序。
4. 我们的 launchd.js agent 然后拦截 launchd 的 *__posix_spawn()* 并添加 [POSIX_SPAWN_START_SUSPENDED][]，并 [signals back][] 标识符和 PID。这是 */usr/libexec/xpcproxy* 辅助程序，它将执行 exec() 风格的转换以成为应用程序。
5. 然后我们将 [xpcproxy.js][] agent 注入其中，以便它可以 hook *__posix_spawn()* 并添加 *POSIX_SPAWN_START_SUSPENDED*，就像我们的 launchd agent 所做的那样。然而，这个也将有 *POSIX_SPAWN_SETEXEC*，这意味着它将用要启动的应用程序替换自己。
6. 我们 *resume()* xpcproxy 进程并 [wait for the exec][] 发生并且进程被挂起。

此时，我们让 *device.spawn()* 返回刚刚启动的应用程序的 PID。应用程序的进程已创建，主线程在 dyld 的入口点挂起。frida-trace 然后想要附加到它，以便它可以加载 hook *open* 的 agent。所以它继续做类似这样的事情：

{% highlight py %}
session = device.attach(pid)
script = session.create_script("""
Interceptor.attach(Module.getExportByName(null, 'open'), {
  onEnter() {
    console.log('open()');
  }
});
""")
script.load()
{% endhighlight %}

现在它已经应用了检测，它将要求 Frida 恢复进程，以便主线程可以调用 *main()* 并享受一些乐趣：

{% highlight py %}
device.resume(pid)
{% endhighlight %}

请注意，我在这里跳过了一些细节，因为 *attach()* 操作实际上由于进程未初始化的程度而稍微复杂一些，但您可以[在这里][here]阅读更多相关信息。

最后，让我们谈谈占用空间和性能。首先，让我们检查当 Frida 安装在 iOS 设备上并处于完全运行状态时需要多少磁盘空间：

<iframe width="600" height="400" src="https://live.amcharts.com/RmODB/embed/" frameborder="0"></iframe>

那是 64 位版本，xz 压缩后只有 1.87 MB。32 位版本显然更小。这里有相当多的优化在起作用：

- 我们过去常常将 frida-helper 二进制文件写出到临时文件并启动它。frida-helper 程序的肉现在静态链接到 frida-server 中，其 entitlements 也随之提升。只有当 Frida 用作未知进程中的插件时，即我们无法对 entitlements 和代码签名做出任何保证的地方，才需要此二进制文件。然而，在 frida-server 案例中，它能够保证满足所有此类约束。
- 我们注入到要检测的进程中的库 *frida-agent.dylib* 不再写出到临时文件。我们使用自己的进程外动态链接器将其从 frida-server 的内存映射并直接映射到目标进程的地址空间。这些映射是写时复制的，这意味着它与旧的 *dlopen()* 方法一样内存高效。
- iOS 二进制文件禁用了 V8，因为它实际上仅在内核打补丁以允许 RWX 页面的旧越狱上可用。（如果 V8 对您的用例很重要，您可以像这样构建它：`make server-ios FRIDA_DIET=no`）
- iOS 包已拆分为两个，"Frida"用于 64 位设备，"Frida for 32-bit devices"用于旧设备。
- 摆脱 iOS 应用程序启动的 Substrate 依赖也意味着我们摆脱了 FridaLoader.dylib。但这只是一个非常小的改进。

好吧，这就是磁盘占用空间。内存使用情况如何？

<iframe width="600" height="400" src="https://live.amcharts.com/jJkYT/embed/" frameborder="0"></iframe>

不错。性能如何？让我们来看看：

<iframe width="600" height="400" src="https://live.amcharts.com/5ZTI5/embed/" frameborder="0"></iframe>

请注意，这些测量包括通过 USB 从 macOS 主机与 iOS 设备通信所花费的时间。

享受吧！


<b id="ios-rwx">1</b> 除非进程具有 entitlement，尽管这仅限于一个区域。[↩](#ios-rwx-sup)

<b id="v8-stack">2</b>: 技术上可以通过在调用 V8 之前切换到每线程侧堆栈来解决这个问题。我们过去实际上已经部分实现了这一点。这可能是我们应该在长期内恢复的东西。[↩](#v8-stack-sup)

[Duktape]: http://duktape.org/
[V8]: https://developers.google.com/v8/
[frida-compile]: https://github.com/frida/frida-compile
[launchd.js]: https://github.com/frida/frida-core/blob/12be27ab171c8bac9b4a60db5b3957f30f4be938/src/darwin/agent/launchd.js
[prepareForLaunch()]: https://github.com/frida/frida-core/blob/12be27ab171c8bac9b4a60db5b3957f30f4be938/src/darwin/agent/launchd.js#L18-L21
[SBSLaunchApplicationWithIdentifierAndLaunchOptions()]: https://github.com/frida/frida-core/blob/12be27ab171c8bac9b4a60db5b3957f30f4be938/src/darwin/frida-helper-backend-glue.m#L560-L563
[POSIX_SPAWN_START_SUSPENDED]: https://github.com/frida/frida-core/blob/12be27ab171c8bac9b4a60db5b3957f30f4be938/src/darwin/agent/launchd.js#L60
[signals back]: https://github.com/frida/frida-core/blob/12be27ab171c8bac9b4a60db5b3957f30f4be938/src/darwin/agent/launchd.js#L85
[xpcproxy.js]: https://github.com/frida/frida-core/blob/12be27ab171c8bac9b4a60db5b3957f30f4be938/src/darwin/agent/xpcproxy.js
[wait for the exec]: https://github.com/frida/frida-core/blob/12be27ab171c8bac9b4a60db5b3957f30f4be938/src/darwin/darwin-host-session.vala#L476-L478
[code]: https://github.com/frida/frida-python/blob/9c876f457cdee4d3dab6c05c8ab8c4bd72ca42d1/src/frida/tracer.py
[here]: https://github.com/frida/frida-core/blob/12be27ab171c8bac9b4a60db5b3957f30f4be938/src/darwin/frida-helper-backend-glue.m#L835-L861
