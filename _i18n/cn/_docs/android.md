在本教程中，我们将展示如何在您的 Android 设备上进行函数跟踪。

## 设置您的 Android 设备

在开始之前，如果您还没有 root 您的设备，您需要先 root。从技术上讲，不 root 设备也可以使用 Frida，例如通过重新打包应用以包含 frida-gadget，或使用调试器来实现相同的目的。但是，对于本介绍，我们将专注于最简单的情况：已 root 的设备。

另请注意，我们最近的大部分测试都是在运行 Android 9 的 Pixel 3 上进行的。较旧的 ROM 可能也可以工作，但是如果您遇到基本问题，例如启动应用程序时 Frida 使系统崩溃，这是由于特定于 ROM 的怪癖。我们无法在所有可能的设备上进行测试，因此我们依靠您的帮助来改进这一点。但是，如果您刚开始使用 Frida，强烈建议使用运行最新官方软件的 Pixel 或 Nexus 设备，或者软件尽可能接近 AOSP 的设备。另一种选择是使用模拟器，最好使用 Google 提供的适用于 arm 或 arm64 的 Android 9 模拟器镜像。（x86 可能也可以工作，但测试明显较少。）

您还需要 Android SDK 中的 `adb` 工具。

首先，从我们的 [releases 页面](https://github.com/frida/frida/releases)下载适用于 Android 的最新 `frida-server` 并解压缩。

{% highlight bash %}
$ adb shell getprop ro.product.cpu.abilist # check your device cpu type

$ unxz frida-server.xz
{% endhighlight %}

现在，让我们在您的设备上运行它：

{% highlight bash %}
$ adb root # might be required
$ adb push frida-server /data/local/tmp/
$ adb shell "chmod 755 /data/local/tmp/frida-server"
$ adb shell "/data/local/tmp/frida-server &"
{% endhighlight %}

某些应用可能能够检测到 frida-server 的位置。将 frida-server 二进制文件重命名为随机名称，或将其移动到另一个位置（如 /dev）可能会奏效。

对于最后一步，请确保以 root 身份启动 frida-server，即如果您在已 root 的设备上执行此操作，您可能需要 *su* 并从该 shell 运行它。

<div class="note info">
  <h5>生产版本上的 adb</h5>
  <p>
    如果在运行 <code>adb root</code> 后收到 <code>adbd cannot run as root in production builds</code><br>您需要在每个 shell 命令前加上 <code>su -c</code>。例如：
    <code>adb shell "su -c chmod 755 /data/local/tmp/frida-server"</code>
  </p>
</div>

接下来，确保 `adb` 可以看到您的设备：

{% highlight bash %}
$ adb devices -l
{% endhighlight %}

这也将确保 adb 守护进程在您的桌面上运行，这允许 Frida 发现并与您的设备通信，无论您是通过 USB 还是 WiFi 连接它。

## 快速冒烟测试

现在，在您的桌面上，是时候确保基础功能正常工作了。运行：

{% highlight bash %}
$ frida-ps -U
{% endhighlight %}

这应该会给您一个类似于以下的进程列表：

{% highlight bash %}
  PID NAME
 1590 com.facebook.katana
13194 com.facebook.katana:providers
12326 com.facebook.orca
13282 com.twitter.android
…
{% endhighlight %}

太棒了，我们可以开始了！

## 跟踪 Chrome 中的 open() 调用

好了，让我们找点乐子。在您的设备上启动 Chrome 应用，然后返回桌面并运行：

{% highlight bash %}
$ frida-trace -U -i open -N com.android.chrome
Uploading data...
open: Auto-generated handler …/linker/open.js
open: Auto-generated handler …/libc.so/open.js
Started tracing 2 functions. Press Ctrl+C to stop.
{% endhighlight %}

现在只需玩一下 Chrome 应用，您应该开始看到 `open()` 调用飞入：

{% highlight bash %}
1392 ms	open()
1403 ms	open()
1420 ms	open()
{% endhighlight %}

您现在可以在阅读 `man open` 时实时编辑上述 JavaScript 文件，并开始越来越深入地研究您的 Android 应用。

## 构建您自己的工具

虽然像 *frida*、*frida-trace* 等 CLI 工具绝对非常有用，但有时您可能希望利用强大的 [Frida API](/docs/javascript-api/) 构建自己的工具。为此，我们建议阅读有关 [Functions](/docs/functions) 和 [Messages](/docs/messages) 的章节，并且在任何看到 `frida.attach()` 的地方，只需将其替换为 `frida.get_usb_device().attach()`。
