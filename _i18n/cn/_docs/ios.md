Frida 支持两种操作模式，具体取决于您的 iOS 设备是否已越狱。

## 目录
  1. [已越狱](#已越狱)
  1. [未越狱](#未越狱)

## 已越狱

这是最强大的设置，因为它允许您以极少的努力对系统服务和应用程序进行插桩。

在本教程中，我们将向您展示如何在 iOS 设备上进行函数跟踪。

### 设置您的 iOS 设备

启动 `Cydia` 并通过转到 `软件源` -> `编辑` -> `添加` 并输入 `https://build.frida.re` 来添加 Frida 的仓库。您现在应该能够找到并安装 `Frida` 包，它允许 Frida 将 JavaScript 注入到 iOS 设备上运行的应用程序中。这是通过 USB 进行的，因此您需要准备好 USB 数据线，尽管还不需要将其插入。

### 快速冒烟测试

现在，回到您的 Windows 或 macOS 系统，是时候确保基础功能正常工作了。运行：

{% highlight bash %}
$ frida-ps -U
{% endhighlight %}

<div class="note info">
  <h5>使用基于 Linux 的操作系统？</h5>
  <p>
    从 Frida 6.0.9 开始，现在有了 usbmuxd 集成，所以 -U 可以工作。
    对于较早的 Frida 版本，您可以使用 WiFi 并在两端的 localhost:27042 之间建立 SSH 隧道，然后使用 -R 代替 -U。
  </p>
</div>

除非您已经插入了设备，否则您应该看到以下消息：

{% highlight text %}
Waiting for USB device to appear...
{% endhighlight %}

插入您的设备，您应该看到一个类似于以下的进程列表：

{% highlight bash %}
 PID NAME
 488 Clock
 116 Facebook
 312 IRCCloud
1711 LinkedIn
…
{% endhighlight %}

太棒了，我们可以开始了！

### 跟踪 Twitter 应用中的加密调用

好了，让我们找点乐子。在您的设备上启动 Twitter 应用，并在确保它保持在前台且设备未进入睡眠状态的同时，返回桌面并运行：

{% highlight bash %}
$ frida-trace -U -i "CCCryptorCreate*" Twitter
Uploading data...
CCCryptorCreate: Auto-generated handler …/CCCryptorCreate.js
CCCryptorCreateFromData: Auto-generated handler …/CCCryptorCreateFromData.js
CCCryptorCreateWithMode: Auto-generated handler …/CCCryptorCreateWithMode.js
CCCryptorCreateFromDataWithMode: Auto-generated handler …/CCCryptorCreateFromDataWithMode.js
Started tracing 4 functions. Press Ctrl+C to stop.
{% endhighlight %}

现在，`CCryptorCreate` 及其朋友是 Apple 的 `libcommonCrypt.dylib` 的一部分，许多应用程序使用它来处理加密、解密、哈希等。

重新加载您的 Twitter feed 或以某种导致网络流量的方式操作 UI，您应该看到类似以下的输出：

{% highlight bash %}
3979 ms	CCCryptorCreate()
3982 ms	CCCryptorCreateWithMode()
3983 ms	CCCryptorCreate()
3983 ms	CCCryptorCreateWithMode()
{% endhighlight %}

您现在可以在阅读 `man CCryptorCreate` 时实时编辑上述 JavaScript 文件，并开始越来越深入地研究您的 iOS 应用。

## 未越狱

Frida 能够对可调试的应用程序进行插桩，并且从 Frida 12.7.12 开始会自动注入 [Gadget](/docs/gadget/)。

只有几个要求需要注意：

- iOS 设备最好运行 iOS 13 或更高版本。对旧版本的支持被认为是实验性的。
- 必须挂载开发者磁盘镜像。Xcode 一旦发现 iOS USB 设备就会自动挂载它，但您也可以使用 *ideviceimagemounter* 手动挂载。
- 最新的 Gadget 必须存在于用户的缓存目录中。在 macOS 上，这是 `~/.cache/frida/gadget-ios.dylib`，但您可以通过尝试附加到可调试应用程序然后读取错误消息来找出确切路径。

## 构建您自己的工具

虽然像 *frida*、*frida-trace* 等 CLI 工具绝对非常有用，但有时您可能希望利用强大的 [Frida API](/docs/javascript-api/) 构建自己的工具。为此，我们建议阅读有关 [Functions](/docs/functions) 和 [Messages](/docs/messages) 的章节，并且在任何看到 `frida.attach()` 的地方，只需将其替换为 `frida.get_usb_device().attach()`。
