---
layout: news_item
title: 'Frida 11.0 发布'
date: 2018-05-05 23:51:56 +0200
author: oleavr
version: 11.0
categories: [release]
---

是时候彻底检修 *spawn()* API 并修复 spawn 和子进程门控 API 中的一些粗糙边缘了。

### spawn()

假设您正在使用 Frida 的 Python 绑定，您目前会这样做：

{% highlight python %}
pid = device.spawn(["/bin/cat", "/etc/passwd"])
{% endhighlight %}

或者启动一个 iOS 应用程序：

{% highlight python %}
pid = device.spawn(["com.apple.mobilesafari"])
{% endhighlight %}

好吧，这就是您实际上可以用该 API 做的所有事情……除了 Python 和 Node.js 绑定没有公开的一件事。我们稍后会谈到这一点。在我们去那里之前，让我们看看 frida-core 中的底层 [API][]，这些绑定将其公开给不同的语言：

{% highlight vala %}
namespace Frida {
	…
	public class Device : GLib.Object {
		…
		public async uint spawn (string path,
			string[] argv, string[] envp)
			throws Frida.Error;
		public uint spawn_sync (string path,
			string[] argv, string[] envp)
			throws Frida.Error;
	}
	…
}
{% endhighlight %}

顺便说一句，那是 [Vala][] 代码，这是 frida-core 编写所用的语言。这是一种类似 C# 的语言，可以编译为 C，而且非常棒。但我离题了。第一个方法 *spawn()* 是异步的，允许调用线程在调用进行时做其他事情，而 *spawn_sync()* 阻塞直到操作完成。

这两个方法编译为以下三个 C 函数：

{% highlight c %}
void frida_device_spawn (FridaDevice * self,
    const gchar * path,
    gchar ** argv, int argv_length,
    gchar ** envp, int envp_length,
    GAsyncReadyCallback callback, gpointer user_data);
guint frida_device_spawn_finish (FridaDevice * self,
    GAsyncResult * result, GError ** error);
guint frida_device_spawn_sync (FridaDevice * self,
    const gchar * path,
    gchar ** argv, int argv_length,
    gchar ** envp, int envp_length,
    GError ** error);
{% endhighlight %}

前两个构成 *spawn()*，您将调用第一个并给它一个回调，一旦该回调被调用，您将调用第二个 *spawn_finish()*，给它您的回调收到的 *GAsyncResult*。返回值是 PID，或者，如果失败，*error* 输出参数解释了出了什么问题。如果您好奇的话，这就是 [GIO][] 异步模式。

至于第三个，*spawn_sync()*，这就是 Frida 的 Python 绑定所使用的。我们的 Node.js 绑定实际上使用前两个，因为这些绑定是完全异步的。有一天，如果能通过集成 Python 3.5 中引入的 *async/await* 支持，将我们的 Python 绑定也迁移到完全异步，那就太好了。

无论如何，回到上面的例子，我提到有一些东西没有公开。如果您仔细观察 frida-core API，您会注意到有 *envp* 字符串数组。窥视绑定的底层，您会意识到我们确实没有公开这个，我们实际上是这样做的：

{% highlight c %}
  envp = g_get_environ ();
  envp_length = g_strv_length (envp);
{% endhighlight %}

所以这意味着我们传递了 Python 进程的任何环境。如果实际的 spawn 发生在完全不同的系统上，比如连接的 iOS 或 Android 设备上，那绝对不好。稍微减轻这个问题的是，在启动 iOS 和 Android 应用程序时 *envp* 被忽略，仅在启动常规程序时使用。

这个旧 API 的另一个问题是声明 *string[] envp* 意味着它不可为空，如果声明是 *string[]? envp* 就可以为空。这意味着无法区分想要在没有任何环境的情况下启动（直观上意味着"使用默认值"）和空环境。

正当我准备修复 API 的这方面时，我意识到是时候修复它的其他几个长期存在的问题了，比如能够：

- 在默认值之上提供一些额外的环境变量
- 设置工作目录
- 自定义 stdio 重定向
- 传递特定于平台的选项

到目前为止，我们总是将 stdio 重定向到我们自己的管道，并通过 *Device* 上的 *output* 信号流式传输任何输出。还有 *Device.input()* 用于写入 *stdin*。这些 API 仍然相同，唯一的区别是我们不再默认进行这种重定向。不过，你们中的大多数人可能并不太在意这一点，因为我们没有为 iOS 和 Android 应用程序实现这种重定向。从这个版本开始，我们终于为 iOS 应用程序实现了它。

到现在为止，您可能想知道新 API 是什么样子的。让我们来看看：

{% highlight vala %}
namespace Frida {
	…
	public class Device : GLib.Object {
		…
		public async uint spawn (string program,
			Frida.SpawnOptions? options = null)
			throws Frida.Error;
		public uint spawn_sync (string program,
			Frida.SpawnOptions? options = null)
			throws Frida.Error;
	}
	…
	public class SpawnOptions : GLib.Object {
		public string[]? argv { get; set; }
		public string[]? envp { get; set; }
		public string[]? env { get; set; }
		public string? cwd { get; set; }
		public Frida.Stdio stdio { get; set; }
		public GLib.VariantDict aux { get; }

		public SpawnOptions ();
	}
	…
}
{% endhighlight %}

回到开头的 Python 示例，这些示例仍然无需任何更改即可工作。但是，代替：

{% highlight python %}
device.spawn(["com.apple.mobilesafari"])
{% endhighlight %}

您现在还可以这样做：

{% highlight python %}
device.spawn("com.apple.mobilesafari")
{% endhighlight %}

因为第一个参数是要启动的 *program*。您仍然可以在这里传递一个 *argv*，它将用于设置 *argv* 选项，这意味着 *argv[0]* 将用于 *program* 参数。您也可以这样做：

{% highlight python %}
device.spawn("/bin/busybox", argv=["/bin/cat", "/etc/passwd"])
{% endhighlight %}

如果您想替换整个环境而不是使用默认值：

{% highlight python %}
device.spawn("/bin/ls", envp={ "CLICOLOR": "1" })
{% endhighlight %}

虽然在大多数情况下，您可能只想添加/覆盖几个环境变量，现在这也是可能的：

{% highlight python %}
device.spawn("/bin/ls", env={ "CLICOLOR": "1" })
{% endhighlight %}

您可能还想使用不同的工作目录：

{% highlight python %}
device.spawn("/bin/ls", cwd="/etc")
{% endhighlight %}

或者也许您想重定向 stdio：

{% highlight python %}
device.spawn("/bin/ls", stdio="pipe")
{% endhighlight %}

如前所述，*stdio* 默认值为 *inherit*。

我们现在已经涵盖了所有的 *SpawnOptions*，除了最后一个：*aux*。这是用于特定于平台的选项的字典。使用 Python 绑定设置此类选项非常简单：任何无法识别的关键字参数最终都会进入该字典。

例如，要启动 Safari 并告诉它打开特定的 URL：

{% highlight python %}
device.spawn("com.apple.mobilesafari", url="https://frida.re")
{% endhighlight %}

或者也许您想在禁用 ASLR 的情况下启动 i/macOS 程序：

{% highlight python %}
device.spawn("/bin/ls", aslr="disable")
{% endhighlight %}

另一个例子是用特定的 activity 启动 Android 应用程序：

{% highlight python %}
spawn("com.android.settings", activity=".SecuritySettings")
{% endhighlight %}

这实际上是我们目前支持的所有 aux 选项 —— 很棒的是我们可以在不需要更新绑定的情况下添加新的选项。

但在我们继续之前，让我们快速看看使用我们的 Node.js 绑定时这个新 API 是什么样子的：

{% highlight js %}
const pid = await device.spawn('/bin/sh', {
  argv: ['/bin/sh', '-c', 'ls /'],
  env: {
    'BADGER': 'badger-badger-badger',
    'SNAKE': true,
    'MUSHROOM': 42,
  },
  cwd: '/usr',
  stdio: 'pipe',
  aslr: 'auto'
});
{% endhighlight %}

如您所见，第二个参数是一个带有选项的对象，那些无法识别的选项最终会进入 aux 字典。

### 11.0.0 中的其余变化

让我们总结一下其余的变化，从 *Device* 类开始：

- *enumerate_pending_spawns()* 现在是 *enumerate_pending_spawn()* 以在语法上正确。
- *spawned* 信号已重命名为 *spawn-added*，现在还有 *spawn-removed*。
- *delivered* 信号已重命名为 *child-added*，现在还有 *child-removed*。

最后的变化是 *Child* 类的 *path*、*argv* 和 *envp* 属性现在都可以为空。这是为了能够区分例如"未提供 *envp*"和"提供了空 *envp*"。

### 11.0.1 中的变化

- core: 修复 32 位 ARM 进程的 agent 线程的堆栈对齐
- core: 修复脆弱的 SELinux 规则修补

### 11.0.2 中的变化

- core: 堵塞 i/macOS 上 spawn() 逻辑中的 Mach 端口泄漏（长期存在的问题）

### 11.0.3 中的变化

- core: 修复 iPhone 8 和 X 上由于 arm64 上错误的 tls_base 计算导致的崩溃

### 11.0.4 中的变化

- python: 更新元数据并提升要求

### 11.0.5 中的变化

- core: 修复与 Electra 的 Tweak Injector 的兼容性问题
- core: 修复 iOS 上 *enumerate_processes()* 中的进程名称截断
- java: Java.registerClass() 现在支持重载
- packaging: 每个新版本现在都附带 Fedora 和 Ubuntu 的包

### 11.0.6 中的变化

- python: 修复依赖规范，以便从 PyPI 安装时 REPL 再次工作

### 11.0.7 中的变化

- core: Windows 上更好的子进程门控 API 覆盖
- python: 从 PyPI 安装时，Linux 的 2.7 二进制文件不再损坏

### 11.0.8 中的变化

- core: 修复导致某些平台上系统会话设置崩溃的竞争
- python: 修复解释器关闭时的死锁

### 11.0.9 中的变化

- java: 修复阻止早期插桩期间 *Java.registerClass()* 的问题

### 11.0.10 中的变化

- core: 修复枚举具有空 DT_GNU_HASH 的 ELF 模块的导入/导出时的崩溃

### 11.0.11 中的变化

- java: 修复类型兼容性检查，这通常导致调用错误的重载，进而导致 VM abort()

### 11.0.12 中的变化

- core: 修复与最新 macOS Mojave 和 iOS 12 beta 的兼容性问题
- core: 改进系统会话（即 PID 0）中可用的 iOS *Kernel* API
- frida-trace: 修复跟踪器脚本 *send()* 任意数据时的崩溃

### 11.0.13 中的变化

- core: 修复从未 *load()* 的脚本的拆卸挂起

### EOF

大概就是这样。如果您没有阅读上周发布的 Frida 10.8 版本，请务必[在这里][here]阅读。

享受吧！


[API]: https://gist.github.com/oleavr/e6af8791adbef8fbde06
[Vala]: https://wiki.gnome.org/Projects/Vala
[GIO]: https://developer.gnome.org/gio/stable/ch02.html
[here]: /news/2018/04/28/frida-10-8-released/
