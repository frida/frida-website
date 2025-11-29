---
layout: news_item
title: 'Frida 7.2 发布'
date: 2016-06-02 23:00:00 +0200
author: oleavr
version: 7.2
categories: [release]
---

你们中的一些人可能知道 Frida 有两个 JavaScript 运行时，一个基于 [V8](https://developers.google.com/v8/)，另一个基于 [Duktape](http://duktape.org/)。我们过去也有一个基于 [JavaScriptCore](https://trac.webkit.org/wiki/JavaScriptCore) 的运行时，但当我们的 Duktape 运行时证明在 V8 不适合的所有情况下（例如在微型嵌入式系统和禁止 RWX 页面的系统上）都更好时，它就退役了。

无论如何，非常整洁的是 Duktape 有一个用于编译为字节码的 API，允许您缓存编译后的代码并在需要检测新进程时节省宝贵的启动时间。从这个版本开始，我们现在有了全新的 API 用于将您的 JavaScript 编译为字节码，当然还有从中实例化脚本。我们的 V8 运行时目前还不支持此 API，但我们应该能够在下次 V8 升级后，通过使用最新版本中开始出现的 WebAssembly 基础设施在那里面实现它。

因此，事不宜迟，让我们通过 *Session.disable_jit()* 强制 Frida 偏向 Duktape，用 Duktape 运行时试用这个新 API。

从 Node.js：

{% highlight js %}
const co = require('co');
const frida = require('frida');

co(function* () {
  const systemSession = yield frida.attach(0);
  yield systemSession.disableJit();
  const bytecode = yield systemSession.compileScript(`
    rpc.exports = {
      listThreads() {
        return Process.enumerateThreadsSync();
      }
    };
  `);

  const session = yield frida.attach('Twitter');
  yield session.disableJit();
  const script = yield session.createScriptFromBytes(bytecode);
  yield script.load();

  const api = yield script.getExports();
  console.log('api.listThreads() =>', yield api.listThreads());

  yield script.unload();
})
.catch(err => {
  console.error(err);
});
{% endhighlight %}

从 Python：

{% highlight python %}
import frida

system_session = frida.attach(0)
system_session.disable_jit()
bytecode = system_session.compile_script("""
rpc.exports = {
  listThreads() {
    return Process.enumerateThreadsSync();
  }
};
""")

session = frida.attach("Twitter")
session.disable_jit()
script = session.create_script_from_bytes(bytecode)
script.load()

api = script.exports
print("api.list_threads() =>", api.list_threads())
{% endhighlight %}

请注意，[Duktape 文档中指定的](http://duktape.org/api.html#duk_load_function)相同警告适用于此处，因此请确保您尝试加载的代码格式正确且由相同版本的 Duktape 生成。当您升级到 Frida 的未来版本时，它可能会升级，但至少是架构中立的；即您可以在 64 位 x86 桌面上编译为字节码，并在 ARM 上的 32 位 iOS 应用程序中正常加载它。

这就是通过 API 进行的字节码编译，但您可能希望使用 [frida-compile](https://github.com/frida/frida-compile) CLI 工具来代替：

{% highlight bash %}
$ npm install frida-compile
$ ./node_modules/.bin/frida-compile agent.js -o agent.bin -b
{% endhighlight %}

在开发时，您还可以通过添加 *-w* 在监视模式下使用它，这使得它监视输入并在其中一个更改时执行快速增量构建。

无论您是否使用字节码 (*-b*)，都强烈建议使用 frida-compile，因为它还附带了许多其他好处，让您：

- 通过使用 *require()* 将脚本拆分为多个 .js 文件。
- 利用 npm 中的数千个现有模块，包括一些 Frida 特定的模块。例如：
  [frida-trace](https://github.com/nowsecure/frida-trace),
  [frida-uikit](https://github.com/nowsecure/frida-uikit),
  [frida-screenshot](https://github.com/nowsecure/frida-screenshot) 等。
- 使用 ES6 语法并将代码编译为 ES5，以便与 Duktape 运行时兼容。

最后，让我们总结一下变化：

7.2.0:

- core: 添加对编译和加载字节码的支持
- core: 在 RPC 错误回复中包含错误名称和堆栈跟踪
- node: 添加对新字节码 API 的支持
- node: 在可用时用 *name* 和 *stack* 增强 RPC 错误
- node: 将示例移植到 ES6
- python: 添加对新字节码 API 的支持
- python: 更新到修订后的 RPC 协议

7.2.1:

- objc: 添加对在最小 Objective-C 代理上解析方法的支持

7.2.2:

- objc: 修复返回结构体和浮点值的方法的处理

7.2.3:

- objc: 公开 Objective-C 方法的原始句柄

7.2.4:

- core: 修复在 iOS 9 上容易重现的死锁
- java: 提高 Java.perform() 的健壮性和非应用程序进程的处理

7.2.5:

- objc: 修复在 x86-64 上返回寄存器中结构体的方法的处理

7.2.6:

- core: 将 Gum 移植到 MIPS
- core: 避免在 Proxy 对象行为不端时吞下异常
- objc: 添加对访问 Objective-C 实例变量的支持

7.2.7:

- core: 将 .so 注入器移植到 MIPS
- core: 用更多分支和链接指令增强 MIPS 模糊回溯器
- core: 修复 TTY 上的 *UnixInputStream* 和 *UnixOutputStream* 可轮询行为，修复脚本卸载时的挂起
- core: 从 *hexdump()* 偏移量中删除"0x"前缀

7.2.8:

- objc: 修复类型提示的解析
- objc: 添加对包含类型提示的支持
- objc: 使 ObjC.Block 的 *types* 字段公开
- objc: 添加对正确声明 *void \** 的支持
- core: (MIPS) 修复获取/设置堆栈参数时的堆栈偏移量

7.2.9:

- core: 修复阻止在 V8 运行时中写入寄存器的错误

7.2.10:

- core: 添加对附加到 iOS 模拟器进程的支持
- core: 修复 7.2.4 中引入的 Android 类解析回归

7.2.11:

- core: 始终通过 SpringBoard 杀死 iOS 应用程序

7.2.12:

- objc: 在卸载和 GC 时注销 Objective-C 类

7.2.13:

- core: 修复 iOS 9 上的应用程序终止逻辑

7.2.14:

- core: 使 Duktape 运行时像 V8 运行时一样可抢占
- core: 修复 V8 运行时中的一些锁定错误

7.2.15:

- core: 在 Duktape 运行时中也实现 *Kernel* API
- core: 删除危险的 *Kernel.enumerateThreads()* API

7.2.16:

- core: 提高快速重新附加到同一进程时的健壮性
- core: 修复分离时存在挂起调用时的死锁
- core: 修复 32 位 ARM 上的 hook 回归
- core: 修复 Linux 上 frida-gadget 中的 *dlsym()* 死锁
- core: 修复 Windows 构建回归
- core: 修复 iOS 7 回归

7.2.17:

- core: 修复会话拆卸回归

7.2.18:

- core: 修复 iOS 9 上长期存在的稳定性问题，即注入的引导代码未伪签名，导致进程最终失去其 *CS_VALID* 状态
- core: 通过消除不必要的磁盘 I/O 加速 iOS 上的应用程序启动
- core: 修复 iOS 上的临时目录清理

7.2.19:

- core: 修复 Duktape 运行时中与抢占相关的生命周期问题

7.2.20:

- core: 重做 V8 运行时以支持完全异步卸载
- core: 重做 Duktape 运行时以支持完全异步卸载
- core: 使 Duktape 运行时完全可重入
- core: 添加 *Script.pin()* 和 *Script.unpin()* 用于在关键时刻延长脚本的生命周期，例如对于预期来自无法控制的外部 API 的回调
- core: 修复 V8 和 Duktape 运行时中与计时器相关的泄漏
- objc: 保持脚本存活直到 *ObjC.schedule()* 调度的回调已执行
- objc: 向 ObjC 代理 API 添加 *dealloc* 事件

7.2.21:

- core: 修复 *detach()* 时的挂起

7.2.22:

- core: 修复脚本卸载时的挂起
- core: 修复 *detach()* 期间突然连接丢失时的挂起

7.2.23:

- core: 修复脚本卸载期间的两个低概率崩溃

7.2.24:

- core: 修复 Duktape 运行时中的 use-after-free
- core: 修复 ModuleApiResolver 中的 use-after-free 错误
- core: 改进设置异常处理程序时的卸载行为

7.2.25:

- core: 修复 iOS 9.3.3 上的应用程序启动
- frida-server: 修复当另一个客户端附加到同一进程时分离时的"挂起"

享受吧！
