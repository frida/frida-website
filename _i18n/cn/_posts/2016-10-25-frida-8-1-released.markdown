---
layout: news_item
title: 'Frida 8.1 发布'
date: 2016-10-25 20:00:00 +0200
author: oleavr
version: 8.1
categories: [release]
---

是时候发布一个版本了，这次我们为那些构建基于 Frida 的工具的人带来了一些重要的新东西，外加一些额外的好东西。让我们从第一部分开始。

毫无疑问，Frida 的 [JavaScript API][] 相当低级，仅旨在提供不属于特定用例的低级构建块。例如，如果您的用例涉及在 iOS 上抓取屏幕截图，这不是人们期望在 Frida 本身中找到的功能。

您可能会想，具有共同功能的不同工具应该如何彼此共享 agent 代码，幸运的是答案不是"复制粘贴"。我们有一个不断增长的 Frida 特定库的 [ecosystem][]，如 [frida-screenshot][]、[frida-uikit][]、[frida-trace][] 等。

也许你们中的一些人会对用于检测用 Java、.NET、Python、Ruby 或 Perl 编写的后端软件的 API 感兴趣，或者也许您想跨不同的操作系统和库跟踪加密 API，或者其他一些很酷的想法。那么我强烈建议您将模块发布到 npm，也许将您的模块命名为 *frida-$name* 以便于发现。

现在您可能会问"但是 Frida 不支持 *require()*，我首先如何将我的 agent 代码拆分为多个文件？"。我很高兴您问了！这就是一个名为 [frida-compile][] 的方便的小 CLI 工具进入画面的地方。

您给它一个 *.js* 文件作为输入，它将负责将其依赖的任何其他文件捆绑到一个文件中。但与使用 *cat* 的自制连接解决方案不同，最终结果还会获得嵌入式源映射，这意味着堆栈跟踪中的文件名和行号是有意义的。模块也被分成单独的闭包，因此变量被包含并且永远不会冲突。您还可以使用最新的 JavaScript 语法，如 [arrow functions][]、[destructuring][] 和 [generator functions][]，因为它会为您将代码编译为 ES5 语法。这意味着您的代码也可以在我们基于 Duktape 的运行时上运行，如果您在受限 iOS 设备上或运行 iOS >= 9 的越狱 iOS 设备上使用 Frida，则必须使用该运行时。

为了在开发时为您提供较短的反馈循环，frida-compile 还通过 *-w* 提供监视模式，因此您在开发 agent 时可以获得即时增量构建。

无论如何，理论够了。让我们看看如何使用 npm 中的现成 Web 应用程序框架，并将其注入任何进程。

首先，确保您安装了最新版本的 Node.js。接下来，创建一个空目录并将以下内容粘贴到名为"package.json"的文件中：

{% highlight json %}
{
  "name": "hello-frida",
  "version": "1.0.0",
  "scripts": {
    "prepublish": "npm run build",
    "build": "frida-compile agent -o _agent.js",
    "watch": "frida-compile agent -o _agent.js -w"
  },
  "devDependencies": {
    "express": "^4.14.0",
    "frida-compile": "^2.0.6"
  }
}
{% endhighlight %}

然后在 agent.js 中，粘贴以下代码：

{% highlight js %}
const express = require('express');

const app = express();

app
  .get('/ranges', (req, res) => {
    res.json(Process.enumerateRangesSync({
      protection: '---',
      coalesce: true
    }));
  })
  .get('/modules', (req, res) => {
    res.json(Process.enumerateModulesSync());
  })
  .get('/modules/:name', (req, res) => {
    try {
      res.json(Process.getModuleByName(req.params.name));
    } catch (e) {
      res.status(404).send(e.message);
    }
  })
  .get('/modules/:name/exports', (req, res) => {
    res.json(Module.enumerateExportsSync(req.params.name));
  })
  .get('/modules/:name/imports', (req, res) => {
    res.json(Module.enumerateImportsSync(req.params.name));
  })
  .get('/objc/classes', (req, res) => {
    if (ObjC.available) {
      res.json(Object.keys(ObjC.classes));
    } else {
      res.status(404).send('Objective-C runtime not available in this process');
    }
  })
  .get('/threads', (req, res) => {
    res.json(Process.enumerateThreadsSync());
  });

app.listen(1337);
{% endhighlight %}

安装 frida-compile 并一步构建您的 agent：

{% highlight bash %}
$ npm install
{% endhighlight %}

然后将生成的 *_agent.js* 加载到正在运行的进程中：

{% highlight bash %}
$ frida Spotify -l _agent.js
{% endhighlight %}

您现在可以用 HTTP 请求访问它：

{% highlight bash %}
$ curl http://127.0.0.1:1337/ranges
$ curl http://127.0.0.1:1337/modules
$ curl http://127.0.0.1:1337/modules/libSystem.B.dylib
$ curl http://127.0.0.1:1337/modules/libSystem.B.dylib/exports
$ curl http://127.0.0.1:1337/modules/libSystem.B.dylib/imports
$ curl http://127.0.0.1:1337/objc/classes
$ curl http://127.0.0.1:1337/threads
{% endhighlight %}

太棒了。我们只用了不到 50 行代码就构建了一个具有 7 个不同端点的进程检查 REST API。这很酷的一点是，我们使用了为 Node.js 编写的现成 Web 应用程序框架。实际上，您可以使用任何依赖于 Node.js 内置 [net][] 和 [http][] 模块的现有模块。比如 [FTP server][]、[IRC client][] 或 [NSQ client][]。

所以在发布此版本之前，您可以使用前面提到的 Frida 特定模块。您还可以使用 npm 中的数千个其他模块，因为它们中的大多数不进行任何 I/O。现在有了这个版本，您还可以访问所有基于 *net* 和 *http* 的模块，这为 Frida 打开了更多很酷的用例。

如果您好奇这是如何实现的，我在 Frida 中添加了 *Socket.listen()* 和 *Socket.connect()*。这些是 [GIO][] 的 [SocketListener][] 和 [SocketClient][] 之上的最小包装器，它们已经是 Frida 技术栈的一部分，并被 Frida 用于其自身需求。所以这意味着我们的占用空间保持不变，没有添加依赖项。因为 frida-compile 在幕后使用 [browserify][]，我们所要做的就是 [plug in] 我们自己的 *net* 和 *http* 内置函数。我只是移植了 Node.js 本身的原始 *net* 和 *http* 模块。

此版本还带来了一些其他好东西。*NativeFunction* 的一个长期限制是，调用需要您读取 *errno* (UNIX) 或调用 *GetLastError()* (Windows) 的系统 API 会很棘手。挑战在于，在您的 *NativeFunction* 调用和您尝试读出错误状态之间，Frida 自己的代码可能会破坏当前线程的错误状态。

进入 *SystemFunction*。它与 *NativeFunction* 完全一样，只是调用返回一个对象，该对象包装了返回值和紧随其后的错误状态。这是一个例子：

{% highlight js %}
const open = new SystemFunction(
    Module.getExportByName(null, 'open'),
    'int',
    ['pointer', 'int']);
const O_RDONLY = 0;

const path = Memory.allocUtf8String('/inexistent');
const result = open(path, O_RDONLY);
console.log(JSON.stringify(result, null, 2));
/*
 * Which on Darwin typically results in the following output:
 *
 * {
 *   "value": -1,
 *   "errno": 2
 * }
 *
 * Where 2 is ENOENT.
 */
{% endhighlight %}

此版本还允许您从传递给 *Interceptor.replace()* 的 *NativeCallback* 中读取和修改此系统错误值，如果您正在替换系统 API，这可能会派上用场。请注意，您已经可以使用 *Interceptor.attach()* 做到这一点，但在您不想调用原始函数的情况下，这不是一个选项。

另一个值得一提的重大变化是我们的 V8 运行时已被大量重构。代码现在更容易理解，添加新功能的工作量也少得多。不仅如此，我们的参数解析也由单个代码路径处理。这意味着我们所有的 API 对错误或缺失的参数都更有弹性，因此您会得到一个 JavaScript 异常，而不是让某些 API 做更少的检查并在您忘记参数的情况下愉快地使目标进程崩溃。

无论如何，这些是亮点。这是更改的完整摘要：

8.1.0:

- core: 添加 *Socket.listen()* 和 *Socket.connect()*
- core: 添加 *setImmediate()* 和 *clearImmediate()*
- core: 改进 *set{Timeout,Interval}()* 以支持传递参数
- core: 修复 Interceptor 脏状态逻辑中与性能相关的错误

8.1.1:

- core: 添加 *Script.nextTick()*

8.1.2:

- core: 教 *Socket.listen()* 和 *Socket.connect()* 关于 UNIX 套接字
- core: 修复 *this.errno* / *this.lastError* 替换函数的处理
- core: 添加 *SystemFunction* API 以在返回时获取 *errno* / *lastError*
- core: 修复使用 Stream API 进行 I/O 期间 *close()* 时的崩溃
- core: 修复并合并 V8 运行时中的参数处理

8.1.3:

- core: 暂时在 macOS 上禁用 Mapper，以确认这是否是报告的稳定性问题的根本原因
- core: 向 NativeFunction 添加 *.call()* 和 *.apply()*
- objc: 修复不透明结构类型的解析

8.1.4:

- core: 修复由无效使用 *v8::Eternal* 引起的 V8 运行时崩溃
- frida-repl: 通过 *-e* 和 *-q* 添加批处理模式支持

8.1.5:

- node: 仅为 6.0 (LTS) 和 7.0 生成预构建

8.1.6:

- node: 除了 6.0 和 7.0 之外，还为 4.0 和 5.0 生成预构建

8.1.7:

- objc: 修复代理某些代理时的无限递归
- objc: 添加对代理非 NSObject 实例的支持
- python: 修复作为成员函数的信号回调的删除

8.1.8:

- core: 实现单指令 ARM 函数的 hook
- core: 堵塞某些架构上不可 hook 函数处理中的泄漏
- core: 修复 *setImmediate()* 回调处理行为
- core: 堵塞 *setTimeout()* 中的泄漏
- core: 修复 Duktape 运行时中处理 *setTimeout(0)* 和 *setImmediate()* 的竞争条件
- core: 修复 Duktape 运行时中处理 tick 回调时的崩溃
- core: 修复 Duktape 运行时中的生命周期问题
- core: 修复 Linux 上报告的模块大小
- core: 修复在较新版本的 Android 上启动应用程序时的崩溃
- core: 修复尝试启动未安装的 Android 应用程序的处理
- core: 通过动态检测 Dalvik 和 ART 字段偏移量，提高与不同版本和风格的 Android 的兼容性
- core: 修复较新版本 Android 上的卸载问题，该问题导致只有第一次 *attach()* 成功，后续尝试全部超时
- core: 将 *ObjC* 和 *Java* 移动到发布到 npm 的自己的模块中，并使用 *frida-compile* 将它们烘焙到 Frida 的内置 JS 运行时中
- java: 通过动态检测 ArtMethod 字段偏移量来改进 ART 支持
- node: 更新依赖项
- node: 修复未处理的 Promise 拒绝问题

8.1.9:

- core: 修复由脚本卸载时的竞争条件引起的 use-after-free

8.1.10:

- core: 使 *ApiResolver* 和 *DebugSymbol* API 可抢占以避免死锁

8.1.11:

- core: 在 macOS 和 iOS 上使用 Mach 异常处理程序，允许我们可靠地捕获已经拥有自己的 Mach 异常处理程序的应用程序中的异常
- core: 修复 Duktape 运行时中 *InvocationContext* 写时复制逻辑中的泄漏，用于在 *onEnter* 和 *onLeave* 之间在 *this* 上存储数据时

8.1.12:

- core: 修复 V8 运行时中的 *Interceptor* 参数替换问题，导致参数仅在第一次被替换

享受吧！


[JavaScript API]: https://frida.re/docs/javascript-api/
[ecosystem]: https://www.npmjs.com/search?q=frida
[frida-screenshot]: https://www.npmjs.com/package/frida-screenshot
[frida-uikit]: https://www.npmjs.com/package/frida-uikit
[frida-trace]: https://www.npmjs.com/package/frida-trace
[frida-compile]: https://www.npmjs.com/package/frida-compile
[arrow functions]: https://developer.mozilla.org/en/docs/Web/JavaScript/Reference/Functions/Arrow_functions
[destructuring]: https://developer.mozilla.org/en/docs/Web/JavaScript/Reference/Operators/Destructuring_assignment
[generator functions]: https://github.com/tj/co
[net]: https://nodejs.org/api/net.html
[http]: https://nodejs.org/api/http.html
[FTP server]: https://github.com/frida/frida-net/tree/master/examples/ftp-server
[IRC client]: https://github.com/frida/frida-net/tree/master/examples/irc-client
[NSQ client]: https://github.com/frida/frida-net/tree/master/examples/nsq-client
[GIO]: https://developer.gnome.org/gio/stable/
[SocketListener]: https://developer.gnome.org/gio/stable/GSocketListener.html
[SocketClient]: https://developer.gnome.org/gio/stable/GSocketClient.html
[browserify]: http://browserify.org/
[plug in]: https://github.com/frida/frida-compile/blob/1eeb38d9453f812e7b404e83cb9b5d0e5dc26241/index.js#L22-L23
