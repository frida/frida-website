---
layout: news_item
title: 'Frida 12.8 发布'
date: 2019-12-18 20:15:00 +0200
author: oleavr
version: 12.8
categories: [release]
---

准备好迎接一个激动人心的新版本。这次我们将对我们的 [Stalker][] 引擎给予一些期待已久的关爱。它已经存在了大约十年，但直到 2017 年底的 Frida 10.5，我们才 [started][] 释放其巨大的潜力。

到目前为止，我们能够 Stalker.follow() 现有线程，不仅观察它们，还可以以任何我们喜欢的方式改变它们的指令流。它还可以与 Interceptor 结合使用，在战略点之间检测当前线程。这使我们能够构建诸如 [AirSpy][] 之类的工具。

但是，如果我们想要 Stalker.follow() 一个 NativeFunction 调用呢？这看起来真的很简单，但可重入性使这真的很难。很容易最终跟踪执行进入例如我们的私有堆，并最终需要为检测本身分配内存……各种有趣的场景让人难以理解。

我们处理这个问题的方法是教 Stalker 排除某些内存范围，这样如果它看到一个调用到这样的位置，它将简单地发出一个调用指令到那里，而不是跟踪执行。所以我们所做的是自动排除 frida-agent 自己的内存范围，这样我们就不必处理任何可重入性的疯狂。

我们还特别注意尝试 Stalker.follow() 当前线程的情况，所以我们将该工作排队，直到我们即将离开我们的运行时并转换回用户代码（或者在 JS 线程的情况下，我们的主循环）。

这仍然留下了如何将 Stalker 与 NativeFunction 结合使用的大问题。我们现在终于可以把这个问题抛在脑后了：

{% highlight js %}
const open = new NativeFunction(
    Module.getExportByName(null, 'open'),
    'int', ['pointer', 'int'],
    { traps: 'all' }
);

Stalker.follow({
  events: {
    call: true
  },
  onReceive(e) {
    console.log(JSON.stringify(Stalker.parse(e)));
  }
});

const fd = open(Memory.allocUtf8String('/foo/bar'), 0);
console.log('open() =>', fd);
{% endhighlight %}

通过在 NativeFunction 上设置 `traps: 'all'` 选项，当从 Stalker 暂时暂停的线程调用时，它将重新激活 Stalker，因为它正在调用一个被排除的范围 —— 这里就是这种情况，因为 frida-agent 的所有代码都被标记为排除。

我们还可以为 Objective-C 方法实现相同的目标：

{% highlight js %}
Stalker.follow({
  events: {
    call: true
  },
  onReceive(e) {
    console.log(JSON.stringify(Stalker.parse(e)));
  }
});

const NSAutoreleasePool = ObjC.classes.NSAutoreleasePool;
const NSFileManager = ObjC.classes.NSFileManager;

const fileExistsAtPath = NSFileManager['- fileExistsAtPath:']
    .clone({ traps: 'all' });

const pool = NSAutoreleasePool.alloc().init();
try {
  const manager = NSFileManager.defaultManager();
  const result = fileExistsAtPath.call(manager, '/foo/bar');
  console.log('fileExistsAtPath() =>', result);
} finally {
  pool.release();
}
{% endhighlight %}

以及 Android 上的 Java 方法：

{% highlight js %}
Stalker.follow({
  events: {
    call: true
  },
  onReceive(e) {
    console.log(JSON.stringify(Stalker.parse(e)));
  }
});

Java.perform(() => {
  const JFile = Java.use('java.io.File');
  const exists = JFile.exists.clone({ traps: 'all' });

  const file = JFile.$new('/foo/bar');
  const result = exists.call(file);
  console.log('exists() =>', result);
});
{% endhighlight %}

耶。也就是说，这些例子几乎没有触及使用 Stalker 可能实现的表面。真正酷的用例之一是进程内模糊测试，[frida-fuzz][] 就是一个很好的例子。还有很多其他用例，例如逆向、测量代码覆盖率、用于测试目的的故障注入、hook 内联系统调用等。

所以这就是这个版本的主要故事。想要感谢 [@andreafioraldi][] 提供的出色错误报告和帮助测试这些棘手的更改。

### 总结

值得一提的一个很酷的新功能是新的 `ArrayBuffer.wrap()` API，它允许您方便高效地访问内存区域，就像它们是 JavaScript 数组一样：

{% highlight js %}
const header = Memory.alloc(16);

const bytes = new Uint8Array(ArrayBuffer.wrap(header, 16));
bytes[0] = 1;
bytes[0] += 2;
bytes[1] = 2;

console.log(hexdump(header, { length: 16, ansi: true }));
console.log('First byte is:', bytes[0]);
{% endhighlight %}

这意味着您可以将直接内存访问权交给 JavaScript API，而无需将内存复制进出运行时。唯一的缺点是坏指针不会导致 JS 异常，而会使进程崩溃。

我们现在还允许您通过 ArrayBuffer 上的新 `unwrap()` 方法访问任何 ArrayBuffer 的后备存储。这方面的一个示例用例是使用现有模块（如 [frida-fs][]）时，您会获得一个 ArrayBuffer，然后希望将其传递给本机代码。

感谢 [@DaveManouchehri][] 贡献了 ArrayBuffer.wrap() API 的第一个草案，也非常感谢 [@CodeColorist][] 建议并帮助塑造 unwrap() 功能。

### 12.8.0 中的变化

- Stalker 重新激活正常工作。
- Stalker 线程生命周期得到正确处理。在 i/macOS 上跟踪线程直到其死亡时也不再崩溃。
- Stalker 中更安全的垃圾收集逻辑。
- 在 Stalker transform 回调中犯错误最终抛出 JS 异常现在会导致 Stalker.unfollow()，因此错误不会被进程崩溃吞没。
- 对 Stalker transform 调用 unfollow() 的强大支持。
- Stalker 支持没有 AVX2 支持的旧 x86 CPU。
- 支持禁用自动 Stalker 队列排空。
- NativeFunction 通过全新的 Interceptor 展开 API 更好地处理异常。
- Java 和 ObjC API 通过 clone(options) 为方法指定 NativeFunction 选项，并通过 ObjC.Block() 的第二个参数为块指定。
- ObjC 类和协议缓存逻辑终于可以工作了。感谢 [@gebing][]！
- Windows 的预构建 Python 3 扩展终于支持 Windows 上所有 Python 3 版本 >= 3.4，就像在其他平台上一样。
- ArrayBuffer wrap() 和 unwrap()。
- DebugSymbol API 在 Linux/Android 上有更好的错误处理。
- Java 集成不再在 Android 10 上的系统进程中的 recompileExceptionClearForArm64() 中崩溃。
- i/macOS 上的 GumJS devkit 再次支持 V8。

### 12.8.1 中的变化

- CModule Stalker 集成恢复正常。

### 12.8.2 中的变化

- Thumb IT 块终于被正确重定位。这意味着我们能够在 32 位 ARM 目标（例如 Android）上 hook 更多函数。感谢 [@bigboysun][]！

### 12.8.3 中的变化

- 引入 Java.ClassFactory.get() 以便能够使用多个类加载器而不必担心类名冲突。这意味着分配给 *loader* 属性现在被认为已弃用。我们仍然保留它以实现向后兼容性，但不支持将其与新 API 一起使用。
- Java.enumerateLoadedClasses() 还提供类句柄，而不仅仅是名称。
- JNI GetByteArrayRegion() 函数现在是 Env 包装器的一部分。感谢 [@iddoeldor][]！

### 12.8.4 中的变化

- 当 PLT/GOT 条目尚未预热时，内部 hook 不再导致 Linux/ELF 目标上的崩溃。

### 12.8.5 中的变化

- Python 绑定终于在 Python 2.x 上提供正确编码的错误消息。

### 12.8.6 中的变化

- Android 链接器检测终于在沙盒进程中再次工作。这是 12.7.8 中引入的回归。感谢 [@DaveManouchehri][] 报告并帮助追踪这个问题！

### 12.8.7 中的变化

- 我们的 Node.js *IOStream* 绑定收到了两个关键的稳定性改进。事实证明，取消逻辑有一个竞争条件，导致可取消对象并不总是被使用。拆卸逻辑中也有一个错误，可能导致在所有 I/O 操作完成之前关闭流。感谢 [@mrmacete][] 提供的这些很棒的修复！

### 12.8.8 中的变化

- Gadget 在 Android/Linux 上的早期插桩用例中不再死锁，其中 Gadget 的入口点在持有动态链接器锁的情况下被调用。由于 Exceptor 现在使用 *dlsym()* 以避免在早期插桩期间遇到 PLT/GOT 问题，我们需要确保 Exceptor 从入口点线程初始化，而不是从 Gadget 线程初始化。

### 12.8.9 中的变化

- Stalker 的 JavaScript 集成不再在 *EventSink::stop()* 中执行 use-after-free，即在 *Stalker.unfollow()* 之后。

### 12.8.10 中的变化

- Gadget 再次能够在没有调试器的情况下在 iOS 上运行。这是 12.8.8 中引入的回归。感谢 [@ddzobov][] 报告！

### 12.8.11 中的变化

- i/macOS Exceptor 的 API hook 在 Mach 异常处理 API 的用户仅请求处理程序的子集时不再执行 OOB 写入。这样的用户通常是崩溃报告器或分析框架。
- 现在为 v8（稳定）和 v9（测试版）提供 Electron 预构建。我们不再为 v7 提供预构建。

### 12.8.12 中的变化

- 大规模改造 Android Java 集成，现在使用 Proxy 对象和 CModule 来延迟解析事物。不再使用 *eval* 来动态生成方法和字段包装器 —— 即每个生成的包装器所需的内存更少。所有这些更改都减少了内存使用量，并允许 *Java.use()* 更快地完成。
- Android Java 集成提供对试图隐藏私有 API 的 Android 版本（即 Android >= 9）上的方法和字段的未经审查的访问。
- 更快的 Android 设备枚举。当本地运行的 ADB 守护程序足够新（即 ADB >= 2017 年某个时候）时，不再运行任何 *adb shell* 命令来确定设备名称。
- 我们终于消除了基于 Linux 的操作系统上的长期内存泄漏，影响受限进程，例如较新版本的 Android 上的 *zygote* 和 *system_server*。这是我们在给定线程退出后不久垃圾收集线程本地数据的逻辑中的一个错误。确定线程确实已完成退出的机制将失败，永远不会认为线程已消失。这将导致越来越多的垃圾积累，垃圾收集要迭代的垃圾越来越长。因此，我们不仅会在徒劳的 GC 尝试上花费越来越多的时间，而且还会每 50 毫秒重试一次 GC 来消耗 CPU。
- Python 绑定允许从 Cancellable 获取文件描述符，以便将其集成到事件循环和其他 *poll()* 风格的用例中。值得注意的是，frida-tools 7.0.1 已发布，其中包含基于此的重大改进：CLI 工具在退出之前不再延迟最多 500 毫秒。因此，像 *frida-ls-devices* 和 *frida-ps* 这样的短期程序现在感觉非常快速。
- Duktape 源映射处理现在也适用于 REPL 加载的脚本 —— 其中内联源映射不是脚本的最后一行，因为 REPL 附加了自己的代码。这意味着堆栈跟踪始终包含有意义的文件名和行号。
- Duktape：内置的 JavaScript 运行时 —— 即 GumJS 的粘合代码、ObjC 和 Java —— 现在使用启用 *loose* 选项的 Babelified，以减少膨胀并提高性能。没有现代 JavaScript 数据结构通过 API 泄漏，因此不需要 Babel 符合规范。
- V8：内置的 JavaScript 运行时被压缩，以获得更小的占用空间和更快的代码。这以前只对 Duktape 进行。
- *enumerate_processes()* 中更好的 Linux 进程名称启发式。

### 12.8.13 中的变化

- *Java.performNow()* 恢复正常工作。
- Python 绑定的 setup.py 现在在尝试下载之前查找本地 *.egg*，并期望下载在两分钟内完成。感谢 [@XieEDeHeiShou][] 提供的这些不错的改进！

### 12.8.14 中的变化

- iOS 模拟器现在得到了正确支持，无论是 Gadget 形式还是从 macOS 附加到正在运行的模拟器进程。感谢 [@insitusec][] 帮助修复这些问题！
- Gadget 现在还在 iOS 上的上面目录中查找其 .config，但仅当其父目录名为"Frameworks"时。感谢 [@insitusec][] 的建议！

### 12.8.15 中的变化

- 全新的功能完整的 iOS/arm64e 支持，包括新的 *NativePointer* 方法：*sign()*、*strip()*、*blend()*。
- 现在支持最新的 iOS Unc0ver 越狱。感谢 [@mrmacete][] 的拉取请求，以及 [@Pwn20wnd][] 的协助！❤️
- 改进了对 Chimera 越狱的支持，确保其 *pspawn_payload-stg2.dylib* 被初始化。感谢 [@mrmacete][]！
- i/macOS 注入器在 agent 入口点立即返回时不再失败。
- 关于需要 Gadget 用于受限 iOS 的更好错误消息。
- 改进了 Windows 注入器中的错误处理，以避免在我们的 DLL 注入失败时使目标进程崩溃。感谢 [@dasraf9][]！
- 支持在 i/macOS 上注入到活动的新生目标，并且不再将挂起的进程视为需要为注入做准备，无论它们是否真的需要。
- 改进了 iOS 容错性，处理最前端 iOS 应用程序名称查询失败。
- 改进了 Android 容错性，处理 *zygote* 和 *system_server* 进程死亡而无需重新启动 *frida-server*。
- 现在能够在 Android 10 上的启动期间启动 *frida-server*，因为 *LD_LIBRARY_PATH* 不再干扰 *frida-helper-32* 的 spawn。感谢 [@enovella][] 帮助追踪这个问题！
- 在 UNIXy 平台上处理 *SIGABRT* 失败时不再无限循环。
- 我们现在在 Exceptor 的 POSIX 后端中支持嵌套信号。感谢 [@bannsec][]！
- 正确处理无效的 Windows ANSI 字符串。感谢 [@clouds56][]！
- *Java.perform()* 在 Android < 5 上再次正常工作。
- 改进了 *NativeFunction* 中的 varargs 处理，现在提升小于 int 的 varargs。感谢报告，[@0x410c][]！

### 12.8.16 中的变化

- 大型 CModule 实例现在可以在具有 16K 页面的 iOS 系统上工作。感谢 [@mrmacete][] 发现并修复这个长期存在的问题！
- Stalker 也可以在 iOS/arm64e 上的 arm64 进程中工作。感谢 [@AeonLucid][] 报告并帮助追踪这个问题！

### 12.8.17 中的变化

- 对 i/macOS 上的活动新生目标的注入支持导致了回归，因此我们暂时恢复了它。具体来说，iOS 12.4 上的 *notifyd* 是 *libSystemInitialized* 未设置的情况。需要更深入地挖掘以弄清楚为什么，所以决定暂时撤回这个逻辑。

### 12.8.18 中的变化

- 新的和改进的 *Java.scheduleOnMainThread()* 以允许调用诸如 *getApplicationContext()* 之类的 API。感谢 [@giantpune][] 报告！
- 能够在较新版本的 Android 上 hook CriticalNative 方法。感谢 [@abdawoud][] 报告！

### 12.8.19 中的变化

- 如果在首次加载之前销毁脚本，现在可以正确清理脚本。这确保了最终当脚本核心被处置时，它反过来处置其对 Exceptor 的引用。如果不这样做，会导致在存在未加载脚本的情况下分离后附加时无限期挂起，因为 Exceptor 线程仍然留在目标进程中。感谢 [@mrmacete][] 发现并修复这个长期存在的问题！

### 12.8.20 中的变化

- *remove_remote_device()* API 恢复正常工作。这是 12.7.17 中引入的不幸回归。感谢报告，[@CodeColorist][]！


[Stalker]: /docs/javascript-api/#stalker
[started]: /news/2017/08/25/frida-10-5-released/
[AirSpy]: https://github.com/nowsecure/airspy
[frida-fuzz]: https://twitter.com/andreafioraldi/status/1205194910372110337
[@andreafioraldi]: https://twitter.com/andreafioraldi
[frida-fs]: https://github.com/nowsecure/frida-fs
[@DaveManouchehri]: https://twitter.com/DaveManouchehri
[@CodeColorist]: https://twitter.com/CodeColorist
[@gebing]: https://github.com/gebing
[@bigboysun]: https://github.com/bigboysun
[@iddoeldor]: https://github.com/iddoeldor
[@mrmacete]: https://twitter.com/bezjaje
[@ddzobov]: https://github.com/ddzobov
[@XieEDeHeiShou]: https://github.com/XieEDeHeiShou
[@insitusec]: https://twitter.com/insitusec
[@Pwn20wnd]: https://twitter.com/Pwn20wnd
[@dasraf9]: https://github.com/dasraf9
[@enovella]: https://twitter.com/enovella_
[@bannsec]: https://twitter.com/bannsec
[@clouds56]: https://github.com/clouds56
[@0x410c]: https://github.com/0x410c
[@AeonLucid]: https://twitter.com/AeonLucid
[@giantpune]: https://twitter.com/giantpune
[@abdawoud]: https://github.com/abdawoud
