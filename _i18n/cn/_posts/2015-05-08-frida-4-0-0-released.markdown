---
layout: news_item
title: 'Frida 4.0.0 发布'
date: 2015-05-08 23:00:00 +0100
author: oleavr
version: 4.0.0
categories: [release]
---

是时候发布一个包含大量改进的疯狂版本了。

让我们从一个面向用户的更改开始。名为 *frida-repl* 的 CLI 工具已重命名为 *frida*，现在可以进行 tab 补全！这个和其他一些很棒的 REPL 好东西是由 [@fitblip](https://github.com/fitblip) 贡献的。

还有对直接从 shell 启动脚本的集成支持：

{% highlight sh %}
$ frida Calculator -l calc.js
    _____
   (_____)
    |   |    Frida 4.0.0 - A world-class dynamic
    |   |                  instrumentation framework
    |`-'|
    |   |    Commands:
    |   |        help      -> Displays the help system
    |   |        object?   -> Display information about 'object'
    |   |        exit/quit -> Exit
    |   |
    |   |    More info at https://frida.re/docs/home/
    `._.'

# The code in calc.js has now been loaded and executed
[Local::ProcName::Calculator]->
# Reload it from file at any time
[Local::ProcName::Calculator]-> %reload
[Local::ProcName::Calculator]->
{% endhighlight %}

或者，也许您厌倦了 console.log() 并想在脚本中设置一些断点以帮助您了解发生了什么？现在您可以了，因为 Frida 刚刚获得了一个集成的 Node.js 兼容调试器。

（这里提示"Yo Dawg"模因。）

是的，但它实际上非常有用，并且所有 CLI 工具都提供 `--debug` 开关来启用它：

{% highlight bash %}
# Connect Frida to a locally-running Calculator.app
# and load calc.js with the debugger enabled
$ frida Calculator -l calc.js --debug
    _____
   (_____)
    |   |    Frida 4.0.0 - A world-class dynamic
    |   |                  instrumentation framework
    |`-'|
    |   |    Commands:
    |   |        help      -> Displays the help system
    |   |        object?   -> Display information about 'object'
    |   |        exit/quit -> Exit
    |   |
    |   |    More info at https://frida.re/docs/home/
    `._.'

Debugger listening on port 5858
# We can now run node-inspector and start debugging calc.js
[Local::ProcName::Calculator]->
{% endhighlight %}

它是这样的：

![Frida Debugger Session](/img/frida-debug.png "Frida Debugger Session")

有没有发现自己想直接从 shell *frida-trace* Objective-C API？感谢 [@Tyilo](https://github.com/Tyilo)，您现在可以了：

{% highlight bash %}
# Trace ObjC method calls in Safari
$ frida-trace -m '-[NSView drawRect:]' Safari
{% endhighlight %}

还有其他好东西，比如对生成回溯和使用调试符号来符号化地址的全新支持：

{% highlight js %}
const f = Module.getExportByName('libcommonCrypto.dylib',
    'CCCryptorCreate');
Interceptor.attach(f, {
    onEnter(args) {
        console.log('CCCryptorCreate called from:\n' +
            Thread.backtrace(this.context, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress).join('\n') + '\n');
    }
});
{% endhighlight %}

或者也许您在 Windows 上并试图弄清楚谁在访问某些内存区域？是吗？好吧，看看全新的 [MemoryAccessMonitor](/docs/javascript-api/#memoryaccessmonitor)。从技术上讲，这段代码并不新鲜，但直到现在它才暴露给 JavaScript API。

另一个不错的功能是，从这个版本开始，当使用在另一台设备（例如 Android）上运行的 `frida-server` 时，不再需要转发多个 TCP 端口。

现在还有更好的错误反馈，从远程进程一直传播到例如 Python 中的不同异常。在以前的版本中，在 Mac 上附加到不存在的 pid 会给您：

{% highlight python %}
SystemError: GDBus.Error:org.gtk.GDBus.UnmappedGError.Quark._g_2↩
dio_2derror_2dquark.Code0: task_for_pid() for remote pid failed w↩
hile trying to make pipe endpoints: (os/kern) failure (5)
{% endhighlight %}

哇，疯狂。现在这很简单：

{% highlight python %}
frida.ProcessNotFoundError: unable to find process with pid 1234
{% endhighlight %}

好多了。让我们谈谈性能。也许您使用了 frida-trace 并想知道为什么它花了这么多时间"Resolving functions..."？在一个典型的 iOS 应用程序上，仅解析一个函数通常需要大约 8 秒。现在降到了约 1 秒。虽然有一些可能的优化，但我很快意识到，无论我们让函数导出的枚举有多快，我们仍然需要传输数据，而仅传输时间就可能是不合理的。解决方案？只需将逻辑移动到目标进程并传输逻辑而不是数据。简单。

此外，Dalvik 和 ObjC 接口已经过优化，因此秒数已减少到毫秒数。这里的简短故事是在我们询问语言运行时时进一步懒惰。我们在 ObjC 接口中走得很远，我们现在使用 ES6 代理来提供更惯用和高效的 API。

这将我们带到下一个主题。ObjC 接口发生了一些变化。本质上：

{% highlight js %}
const NSString = ObjC.use("NSString");
{% endhighlight %}

现在是：

{% highlight js %}
const NSString = ObjC.classes.NSString;
{% endhighlight %}

您仍然使用 `ObjC.classes` 来枚举当前加载的类，但这现在的行为就像一个将类名映射到 JavaScript ObjC 绑定的对象。

此外，不再有转换，所以代替：

{% highlight js %}
const NSSound = ObjC.use('NSSound');
const sound = ObjC.cast(ptr("0x1234"), NSSound);
{% endhighlight %}

您只需：

{% highlight js %}
const sound = new ObjC.Object(ptr("0x1234"));
{% endhighlight %}

是的，不再有类层次结构试图模仿 ObjC 的类层次结构。只是一个完全动态的包装器，其中方法包装器是在第一次访问时构建的，除非您尝试枚举对象的属性，否则不会获取方法列表。

无论如何，这变得很长，所以让我们总结一下其他关键变化：

- Dalvik 接口现在处理可变参数方法。感谢 [@dmchell](https://github.com/dmchell) 报告并帮助追踪此问题。
- *NativePointer* 还提供 `.and()`、`.or()` 和 `.xor()`，感谢 [@Tyilo](https://github.com/Tyilo)。
- Interceptor 的 *onEnter*/*onLeave* 回调过去通过 `this.registers` 公开 CPU 寄存器，该寄存器已重命名为 `this.context`，现在也允许您写入寄存器。
- *Process.enumerateThreads()* 的线程对象的 CPU 上下文字段从 `registers` 重命名为 `context` 以保持一致性。
- enumerateFoo() API 的同步版本可用作 enumerateFoo**Sync**() 方法，该方法只需返回包含所有项目的数组。
- `Memory.readCString()` 现在可用于读取 ASCII C 字符串。
- 可以查询 `Frida.version` 以检查您正在运行的版本，这也在 *frida-core* 端提供，例如由 *frida-python* 通过 `frida.__version__` 公开。
- *Stalker* 现在支持 *jecxz* 和 *jrcxz* 指令。这对 [CryptoShark](https://github.com/frida/cryptoshark) 来说是个好消息，它应该很快提供一些更新的二进制文件来捆绑最新版本的 Frida。
- V8 已更新至 4.3.62，并且已启用许多 ES6 功能。
- 我们现在使用的是即将推出的 Capstone 4.0 的开发版本。
- 所有第三方依赖项已更新到最新和最好的版本。
- 现在支持 Windows XP。这不是玩笑。我意识到我们实际上没有使用任何 XP 后的 API，而且由于我必须在 Windows 上重建依赖项，我想我们不妨降低我们的操作系统要求，以帮助那些仍在 XP 上插桩软件的人。

享受吧！
