---
layout: news_item
title: 'Frida 12.7 发布'
date: 2019-09-18 23:00:00 +0200
author: oleavr
version: 12.7
categories: [release]
---

这次只有一个新功能，但这是一个大功能。我们要解决房间里的大象：性能。

虽然 Frida 的检测核心 Gum 是用 C 编写的，并且可以从 C 使用，但大多数用例最好使用其 JavaScript 绑定。

然而，在某些情况下，性能会成为问题。即使使用我们基于 V8 的运行时，这意味着您的 JavaScript 将在运行时进行分析，并根据热点所在进行优化……（顺便说一句，这太棒了 —— V8 确实是一项令人印象深刻的工程壮举！）

……进入和离开 JavaScript VM 还是有一点代价的。在 iPhone 5S 上，如果您使用 *Interceptor.attach()* 并且只指定 *onEnter* 并将其留空，这可能相当于大约 6 微秒。

这听起来可能并不多，但如果一个函数被调用一百万次，它将增加 6 秒的开销。也许 hook 只需要做一些非常简单的事情，所以大部分时间实际上都花在了进入和离开 VM 上。

当需要将回调传递给 API 时也存在同样的问题，API 会遍历可能数百万个项目，并需要为每个项目调用回调。回调可能只查看一个字节并收集符合特定条件的少数项目。

天真地，人们可以继续使用 NativeCallback 来实现该回调，但很快就会发现这根本无法扩展。

或者，您可能正在编写一个 fuzzer，并且需要在紧密循环中调用 NativeFunction，进入/离开 VM 加上 libffi 的成本就会增加。

除了用 C 编写整个 agent 之外，人们可以继续构建本机库，并使用 *Module.load()* 加载它。这可行，但意味着必须为每个架构编译它，部署到目标等。

另一种解决方案是使用 X86Writer/Arm64Writer/etc. API 在运行时生成代码。这也是痛苦的，因为每个要支持的架构都需要做相当多的工作。但直到现在，这是在诸如 [frida-java-bridge][] 之类的模块中使用的唯一可移植选项。

但现在我们终于有了更好的东西。进入 **CModule**：

![CModule Hello World](/img/cmodule-hello-world.png "CModule Hello World")

它获取 C 源代码字符串并将其编译为机器代码，直接存入内存。这是使用 [TinyCC][] 实现的，这意味着此功能仅为 Frida 增加了约 100 kB 的占用空间。

如您所见，任何全局函数都会自动导出为 NativePointer 属性，其名称与 C 源代码中的完全相同。

而且，它很快：

![CModule Speed](/img/cmodule-speed.png "CModule Speed")

（在 Intel i7 @ 3.1 GHz 上测量。）

我们还可以将此新功能与 Interceptor 等 API 结合使用：

{% highlight js %}
const m = new CModule(`
#include <gum/guminterceptor.h>

#define EPERM 1

int
open (const char * path,
      int oflag,
      ...)
{
  GumInvocationContext * ic;

  ic = gum_interceptor_get_current_invocation ();
  ic->system_error = EPERM;

  return -1;
}
`);

const openImpl = Module.getExportByName(null, 'open');

Interceptor.replace(openImpl, m.open);
{% endhighlight %}

（请注意，此示例和以下示例使用现代 JavaScript 功能，如模板文字，因此它们要么需要在我们的 V8 运行时上运行，要么使用 [frida-compile][] 编译。）

我们还可以将其与 *Interceptor.attach()* 结合使用：

{% highlight js %}
const openImpl = Module.getExportByName(null, 'open');

Interceptor.attach(openImpl, new CModule(`
  #include <gum/guminterceptor.h>
  #include <stdio.h>

  void
  onEnter (GumInvocationContext * ic)
  {
    const char * path;

    path = gum_invocation_context_get_nth_argument (ic, 0);

    printf ("open() path=\\"%s\\"\\n", path);
  }

  void
  onLeave (GumInvocationContext * ic)
  {
    int fd;

    fd = (int) gum_invocation_context_get_return_value (ic);

    printf ("=> fd=%d\\n", fd);
  }
`));
{% endhighlight %}

耶。虽然这最后一个特定的例子实际上写入了目标进程的 *stdout*，这对于调试来说很好，但可能并不那么有用。

但是，我们可以通过回调 JavaScript 来解决这个问题。让我们看看那可能是什么样子：

{% highlight js %}
const openImpl = Module.getExportByName(null, 'open');

Interceptor.attach(openImpl, new CModule(`
  #include <gum/guminterceptor.h>

  extern void onMessage (const gchar * message);

  static void log (const gchar * format, ...);

  void
  onEnter (GumInvocationContext * ic)
  {
    const char * path;

    path = gum_invocation_context_get_nth_argument (ic, 0);

    log ("open() path=\\"%s\\"", path);
  }

  void
  onLeave (GumInvocationContext * ic)
  {
    int fd;

    fd = (int) gum_invocation_context_get_return_value (ic);

    log ("=> fd=%d", fd);
  }

  static void
  log (const gchar * format,
       ...)
  {
    gchar * message;
    va_list args;

    va_start (args, format);
    message = g_strdup_vprintf (format, args);
    va_end (args);

    onMessage (message);

    g_free (message);
  }
`, {
  onMessage: new NativeCallback(messagePtr => {
    const message = messagePtr.readUtf8String();
    console.log('onMessage:', message);
  }, 'void', ['pointer'])
}));
{% endhighlight %}

然而，这只是一个玩具示例：以这种方式做实际上会违背用 C 编写 hook 以提高性能的目的。真正的实现可能会在获取 [GLib.Mutex][] 后附加到 [GLib.Array][]，并通过回调 JS 定期刷新缓冲数据。

就像可以从 C 调用 JavaScript 函数一样，我们也可以在两个领域之间共享数据：

{% highlight js %}
const calls = Memory.alloc(4);

const openImpl = Module.getExportByName(null, 'open');

Interceptor.attach(openImpl, new CModule(`
  #include <gum/guminterceptor.h>

  extern volatile gint calls;

  void
  onEnter (GumInvocationContext * ic)
  {
    g_atomic_int_add (&calls, 1);
  }
`, { calls }));

setInterval(() => {
  console.log('Calls so far:', calls.readInt());
}, 1000);
{% endhighlight %}

目前我们没有任何关于内置 C API 的文档，但您可以浏览 [frida-gum/bindings/gumjs/runtime/cmodule][] 中的头文件以获得概览。将函数名称放入互联网搜索引擎中以查找非 Frida API（如 GLib）的文档。

目的是只公开标准 C 库、GLib、JSON-GLib 和 Gum API 的最小子集；以尽量减少膨胀并最大化性能。我们包含的内容应该是通过调用 JS 无法实现的，或者以这种方式实现成本过高的。

将 JS 端视为操作系统，您插入其中的函数是系统调用；并且仅使用 CModule 来 hook 热点函数或实现高性能粘合代码，如传递给性能敏感 API 的回调。

还要记住，TinyCC 生成的机器代码不如 Clang 或 GCC 的效率高，因此计算昂贵的算法实际上可能在 JavaScript 中实现得更快。（当使用我们基于 V8 的运行时。）但对于 hook 和粘合代码，这种差异并不显着，如果您需要优化内部循环，您总是可以使用例如 Arm64Writer 生成机器代码并插入您的 CModule。

一个重要的警告是所有数据都是只读的，因此可写全局变量应声明为 *extern*，使用例如 *Memory.alloc()* 分配，并通过构造函数的第二个参数作为符号传入。（就像我们在上一个示例中对 `calls` 所做的那样。）

您可能还需要在 CModule 被销毁时初始化事物并清理它们 —— 例如因为脚本被卸载 —— 我们为此类目的提供了几个生命周期 hook：

{% highlight js %}
const cm = new CModule(`
#include <stdio.h>

void
init (void)
{
  printf ("init\\n");
}

void
finalize (void)
{
  printf ("finalize\\n");
}
`);

cm.dispose(); // or wait until it gets GCed or script unloaded
{% endhighlight %}

无论如何，这篇文章越来越长，但在我们结束之前，让我们看看如何将 CModule 与 Stalker API 一起使用：

{% highlight js %}
const cm = new CModule(`
#include <gum/gumstalker.h>

static void on_ret (GumCpuContext * cpu_context,
    gpointer user_data);

void
transform (GumStalkerIterator * iterator,
           GumStalkerOutput * output,
           gpointer user_data)
{
  cs_insn * insn;

  while (gum_stalker_iterator_next (iterator, &insn))
  {
    if (insn->id == X86_INS_RET)
    {
      gum_x86_writer_put_nop (output->writer.x86);
      gum_stalker_iterator_put_callout (iterator,
          on_ret, NULL, NULL);
    }

    gum_stalker_iterator_keep (iterator);
  }
}

static void
on_ret (GumCpuContext * cpu_context,
        gpointer user_data)
{
  printf ("on_ret!\n");
}
`);

const mainThread = Process.enumerateThreads()[0];

Stalker.follow(mainThread.id, {
  transform: cm.transform,
  data: ptr(1337)
});
{% endhighlight %}

这展示了如何用 C 实现 transform 回调和 callout，但您也可以使用混合方法，其中用 JS 编写 transform 回调，只用 C 编写部分 callout。

还值得注意的是，我重写了 *ObjC.choose()* 以使用 CModule，现在它的速度大约快了 100 倍。当在 iPhone 6S 上的 Twitter 应用程序的登录屏幕上测试它时，这从大约需要 5 秒变为现在只需要约 50 毫秒。

因此，我希望您会喜欢这个版本。很高兴看到您将使用新的 CModule API 构建什么样的东西。我真正期待的一件事是改进我们的 REPL 以支持在 *.js* 旁边加载 *.c* 文件，以便进行快速原型设计。

享受吧！


### 12.7.0 中的变化

- 由 TinyCC 提供支持的全新 CModule API。（您刚刚读到了。）
- TinyCC 得到改进，以支持 macOS/x86 上的 Apple ABI。
- *Stalker.exclude()* 现在暴露给 JS，以便能够将特定内存范围标记为排除。这对于提高性能和减少噪音很有用。
- 感谢 [@gebing][] 的巧妙贡献，现在支持对 *Java.use()* 的并发调用。
- *hexdump()* 实现得到改进，将 *length* 选项限制为 ArrayBuffer 的长度，感谢 [@gebing][] 的另一个巧妙贡献。

### 12.7.1 中的变化

- 更多 CModule 好东西，包括 [GLib.String][]、[GLib.Timer][] 和 [Json.Builder][]。
- TinyCC 得到改进，以支持 iOS/arm64 上的 Apple ABI。
- *ObjC.choose()* 使用 CModule 重写，现在快了约 100 倍。

### 12.7.2 中的变化

- CModule 获得了一些缺失的引用计数 API。

### 12.7.3 中的变化

- CModule 内存范围现在被正确隐藏。
- V8 垃圾收集器现在被告知外部分配的 CModule 内存，以便它可以更好地决定何时进行 GC。
- 附加到 CModule 的符号现在也在 V8 运行时中正确保持活动状态；并且 CModule 本身不会无限期地保持活动状态（或直到脚本卸载）。
- 添加了 *CModule.dispose()* 用于急切地清理内存。

### 12.7.4 中的变化

- *frida-inject* 工具现在支持 *spawn()*。感谢 [@hunterli][] 贡献这个巧妙的功能。
- 我们的 V8 运行时在 i/macOS 上不再死锁，当 *thread_suspend()* 在仍然持有 JS 锁的情况下被调用时，就像 *Stalker.follow()* 在被要求跟踪另一个线程时间接做的那样。

### 12.7.5 中的变化

- 全新的通道 API，用于建立到系留 iOS 或 Android 设备的 TCP 连接，以及与系留 iOS 设备上的 lockdown 服务对话。
- *DeviceManager.find_device()* 及其兄弟方法背后的超时逻辑现在正常工作。
- *java.lang.Class* 的 Java 编组现在正常工作，并且实例字段也可以在不需要实例的情况下进行内省。感谢 [@gebing][] 贡献这些巧妙的修复！

### 12.7.6 中的变化

- Android 链接器现在在 Android 10 上被正确检测。
- 我们的 Android SELinux 策略修补程序现在也处理像三星 S10 这样的设备，感谢 [@cbayet][] 的巧妙贡献。
- *frida-inject* 工具现在支持 *-D/--device* 以使用非本地设备。
- 我们现在有更好的错误处理，以避免在 i/macOS 进程在早期插桩期间意外终止时崩溃。
- iOS 崩溃报告器集成更加强大，感谢 [@mrmacete][] 贡献的一些很棒的修复。他的一个修复还确保对同一消息类型的 *recv().wait()* 的并行调用不会导致无限等待。
- Linux/arm64 上现在支持跟踪线程创建。感谢 [@alvaro_fe][] 的这个很棒的贡献！
- V8 运行时的 WebAssembly 支持在非 iOS 上也再次工作。
- *Gum.DarwinModule* API 现在是跨平台 Gum API 的一部分。用于在非 Apple 系统上解析 Mach-O 文件。

### 12.7.7 中的变化

- 永恒化的 agent 现在在最后一个会话关闭时保留，这意味着只要 *HostSession* 端（例如 frida-server）存在，它们就可以重用。这意味着在很多情况下可以避免 frida-agent 的额外副本。感谢 [@mrmacete][] 提供的这个很棒的改进。
- Java bridge 在方法返回 *this* 时不再触发 use-after-free。
- 我们的 Android SELinux 策略修补程序不再在旧版本的 Android 上打印警告。这个无害但令人困惑的回归是由上一版本针对三星 S10 ROM 的修复引入的。
- 更好的 SELinux 相关错误消息。
- 对 iOS/arm64e 的基本支持。

### 12.7.8 中的变化

- 感谢 [@Alien-AV][] 的精彩贡献，Android 10 支持刚刚登陆我们的 Java bridge。
- 更好的 Android 应用程序 spawn() 处理，其中 *activity* 参数可用于应用程序没有启动器活动的情况。这个巧妙的改进是由 [@muhzii][] 贡献的。
- 感谢 [@timstrazz][] 的优雅贡献，Android 链接器搜索逻辑变得面向未来。
- 大规模改进了 iOS 上的容错性：我们的 launchd agent 现在在卸载时杀死挂起的进程。这意味着 frida-server 死亡不会让进程卡在挂起状态。感谢 [@mrmacete][] 提供的这个很棒的改进。

### 12.7.9 中的变化

- 在上一版本中潜入最后一分钟的构建回归后，我们在 macOS 上恢复了业务。

### 12.7.10 中的变化

- *MemoryAccessMonitor* 现在在所有平台上可用，甚至 Duktape 运行时。感谢 [@alvaro_fe][] 提供的这些很棒的改进。
- Android 链接器检测再次正常工作。（12.7.8 中引入的回归。）
- Gadget 得到改进，支持在 i/macOS 上通过其构造函数传递配置。
- Gadget 的系统循环集成 —— 仅在 i/macOS 上实现 —— 被删除，以避免在某些情况下出现未定义的行为。

### 12.7.11 中的变化

- Frida 不再在没有 vDSO 的 Android 进程中崩溃。（12.7.8 中引入的回归。）
- 解析 Mach-O 图像时更好的错误处理。
- 在 i/macOS 上恢复异常时正确处理 ARM 与 Thumb。感谢 [@alvaro_fe][]！
- CModule 的 JSON-GLib 头文件现在是自包含的，正如它应该的那样。

### 12.7.12 中的变化

- 功能齐全的 iOS lockdown 集成和统一设备，因此基于 Frida 的工具不需要太担心 jailed 与 jailbroken。当与受限 iOS 设备交互时，Gadget 现在会自动注入，无需重新打包应用程序，它只需要是可调试的。
- Frida 终于能够在 Windows 上检测最近的 iOS 设备。
- V8 中的错误被追踪并从上游反向移植修复。感谢 [@mrmacete][] 追踪这个问题！

### 12.7.13 中的变化

- 更好地处理 *frida-objc-bridge* 中的结构和联合。感谢 [@gebing][]！
- 我们的 Node.js 绑定现在还公开 *Crash* 和 *CrashParameters* 的类型定义。
- 尝试附加到受限 iOS 上的系统会话会提前抛出并带有更清晰的错误消息。
- iOS 开发者磁盘映像相关的错误消息为了保持一致性进行了调整。

### 12.7.14 中的变化

- Frida 现在确保在 Android >= 10 上访问代码之前它是可读的。这是功能齐全的 Android 10 支持的最后一块缺失拼图。能够检测系统进程意味着早期插桩 —— 即 spawn() —— 工作，并且启动 frida-server 不会因其尝试预加载而导致 *system_server* 崩溃，因此第一次 *spawn()* 将很快。感谢 [@Alien-AV][] 和 [@esanfelix][] 进行的痛苦研究，使得在一个深夜的星期六晚上实现解决方案成为可能。:-)

### 12.7.15 中的变化

- Node.js 绑定还公开 *Crash* 类型的"summary"字段。

### 12.7.16 中的变化

- *frida-gadget-ios* 元包附带类型定义，因此可以从 TypeScript 使用。
- Node.js 绑定为 *Stdio* 和 *ChildOrigin* 提供适当的类型。

### 12.7.17 中的变化

- 对受限 iOS 的更强大支持：在 attach() 之后但在 resume() 之前调用 kill() 现在正常工作。
- Frida 现在尽可能直接与远程 iOS/Android agent 通信。我们通过建立到 frida-server 的新 TCP 连接并将其文件描述符传递给 agent 来实现这一点。这意味着 frida-server 可以从数据路径中移除自身，从而提高性能和可靠性。
- 连接到 frida-server 以 spawn() 进程，但在有机会 resume() 或 kill() 该进程之前断开连接的客户端，将不再让这些孤儿处于不确定状态。我们现在跟踪生成的进程，如果客户端突然断开连接，则 kill() 它们。
- 我们不再使 Android 10 上的 Zygote 崩溃。原来是缺少 SELinux 规则。
- 我们的 TCP 套接字现在设置了 *TCP_NODELAY*，并且我们还支持除了 TCP 之外使用 UNIX 套接字与远程 frida-server 或 frida-gadget 通信。
- NativeFunction 现在支持可变参数函数，以避免需要为每个唯一的参数列表签名创建一个实例。感谢 [@gebing][]！

### 12.7.18 中的变化

- Node.js 绑定终于在 UNIX 上链接所需的 OpenSSL 符号，而不是依赖运气，我们通常会在已经加载了另一个全局可见 *且* ABI 兼容 (!) 的 OpenSSL 的进程中结束。

### 12.7.19 中的变化

- 我们现在还在 V8 运行时中正确处理无参数 NativeFunction 上的 apply()。感谢 [@taviso][] 报告这个长期存在的错误。
- NativeFunction 在 call() 和 apply() 中对可选参数的处理现在表现得像内置对应物一样。

### 12.7.20 中的变化

- Frida 现在支持明文和加密的 iOS lockdown 通道，通过在通道地址后附加 "?tls=handshake-only" 来保留对"仅 TLS 握手后明文"风格通道的支持。感谢，[@mrmacete][]！
- 配对的 lockdown 通道本身可以通过使用 "lockdown:" 作为通道地址来访问。感谢 [@mrmacete][]！

### 12.7.21 中的变化

- 我们现在在 checkra1n 越狱上支持 iOS 13。（受限 iOS 13 已经支持。）

### 12.7.22 中的变化

- 我们的 iOS 包脚本启动守护程序逻辑现在与 checkra1n 兼容，因此不必手动启动/停止 frida-server。

### 12.7.23 中的变化

- 增强了对 checkra1n 越狱的支持：Stalker 现在快得多，因为它利用了 RWX 页面。
- 在没有 RWX 支持的越狱上在 iOS 上使用 Stalker 时的稳定性改进。感谢 [@mrmacete][]！
- CModule 现在与更多 iOS 越狱版本兼容。感谢，[@mrmacete][]！
- CModule 运行时支持使用 ModuleMap 对象。
- 感谢 [Jon Wilson][] 的出色贡献，支持 ARMBE8。
- Frida 现在在 i/macOS 上 spawn() 时使父文件描述符对子进程可用。这与 Linux 上的当前行为一致。感谢 [@wizche][]！

### 12.7.24 中的变化

- 还为 Node.js v13 提供了 Node.js 预构建。

### 12.7.25 中的变化

- 日志处理程序 API 在 Python 和 Node.js 绑定中进行了大修，作为关键修复的一部分：Node.js setter 的类型与 getter 不同，因为它还允许 *null*。这种不一致导致最近的 TypeScript 编译器版本对其窒息。感谢 [@mrmacete][]！
- V8 平台集成中不再有时间戳截断。感谢报告，[@DaveManouchehri][]！
- 我们的 *Module.enumerateSymbols()* API 在可用时提供"size"属性，即目前仅在 Linux/Android 上。感谢 [@DaveManouchehri][]！
- *Java.use(name, { cache: 'skip' })* 现在可用于绕过缓存。在处理多个类加载器和冲突的类名时很有用。感谢 [@ChaosData][] 和 [@H4oK3][]！

### 12.7.26 中的变化

- Stalker 现在支持临时重新激活，以允许从排除的内存范围内部跟踪代码。
- NativeFunction 获得了一个全新的选项 `traps: 'all'`，即使 Frida 自己的内存范围被标记为排除，也允许跟踪调用。
- 使用 Yama 时，Linux 上的线程枚举终于可以工作了。感谢 [Jon Wilson][]！


[frida-java-bridge]: https://github.com/frida/frida-java-bridge
[TinyCC]: https://bellard.org/tcc/
[frida-compile]: https://github.com/oleavr/frida-agent-example
[GLib.Array]: https://developer.gnome.org/glib/stable/glib-Arrays.html
[GLib.Mutex]: https://developer.gnome.org/glib/stable/glib-Threads.html#GMutex
[frida-gum/bindings/gumjs/runtime/cmodule]: https://github.com/frida/frida-gum/tree/master/bindings/gumjs/runtime/cmodule
[@gebing]: https://github.com/gebing
[GLib.String]: https://developer.gnome.org/glib/stable/glib-Strings.html
[GLib.Timer]: https://developer.gnome.org/glib/stable/glib-Timers.html
[Json.Builder]: https://developer.gnome.org/json-glib/stable/JsonBuilder.html
[@hunterli]: https://github.com/hunterli
[@cbayet]: https://github.com/cbayet
[@mrmacete]: https://twitter.com/bezjaje
[@alvaro_fe]: https://twitter.com/alvaro_fe
[@Alien-AV]: https://github.com/Alien-AV
[@muhzii]: https://github.com/muhzii
[@timstrazz]: https://twitter.com/timstrazz
[@esanfelix]: https://twitter.com/esanfelix
[@taviso]: https://twitter.com/taviso
[Jon Wilson]: https://github.com/jonwilson030981
[@wizche]: https://twitter.com/wizche
[@DaveManouchehri]: https://twitter.com/DaveManouchehri
[@ChaosData]: https://github.com/ChaosData
[@H4oK3]: https://github.com/H4oK3
