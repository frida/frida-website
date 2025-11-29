---
layout: news_item
title: 'Frida 15.2.0 发布'
date: 2022-07-21 00:02:32 +0200
author: oleavr
version: 15.2.0
categories: [release]
---

对此感到非常兴奋。多年来我一直想做的是简化 Frida 的 JavaScript 开发人员体验。作为一名开发人员，我可能从一个非常简单的代理开始，但随着它的增长，我开始感到痛苦。

早期我可能想将代理拆分为多个文件。我也可能想使用 npm 中的一些现成包，例如 [frida-remote-stream][]。稍后我会想要代码补全、内联文档、类型检查等，所以我将代理迁移到 TypeScript 并启动 VS Code。

由于我们一直在利用现有的令人惊叹的前端 Web 工具，我们已经拥有了所有的拼图。我们可以使用像 [Rollup][] 这样的打包器将我们的源文件合并为一个 .js，我们可以使用 [@frida/rollup-plugin-node-polyfills][] 与 npm 包进行互操作，我们可以插入 [@rollup/plugin-typescript][] 以获得 TypeScript 支持。

但这需要反复设置大量的管道，所以我最终创建了 [frida-compile][] 作为一个简单的工具，它可以为您完成管道工作，并针对 Frida 上下文进行了优化配置默认值。不过，这仍然需要一些样板文件，例如 package.json, tsconfig.json 等。

为了解决这个问题，我发布了 [frida-agent-example][]，这是一个可以克隆并用作起点的 repo。这仍然有点摩擦，所以后来 frida-tools 获得了一个名为 frida-create 的新 CLI 工具。无论如何，即使有了所有这些，我们仍然要求用户安装 Node.js 并处理 npm，并且可能还会对那里的 .json 文件感到困惑。

然后我突然想到了。如果我们能够使用 frida-compile 将 frida-compile 编译成一个独立的 .js，我们可以在 Frida 的系统会话上运行它，那会怎么样？系统会话是一个有点晦涩的功能，您可以在托管 frida-core 的进程内加载脚本。例如，如果您正在使用我们的 Python 绑定，该进程将是 Python 解释器。

一旦我们能够在 GumJS 中运行该 frida-compile 代理，我们就可以与它通信并将其转化为 API。然后，此 API 可以由语言绑定公开，并且 frida-tools 可以使用它来为用户提供不需要安装 Node.js/npm 的 frida-compile CLI 工具。如果用户要求加载具有 .ts 扩展名的脚本，诸如我们的 REPL 之类的工具也可以无缝使用此 API。

所有这些正是我们所做的！🥳

## build()

这是从 Python 使用它有多容易：

{% highlight python %}
import frida

compiler = frida.Compiler()
bundle = compiler.build("agent.ts")
{% endhighlight %}

*bundle* 变量是一个字符串，可以传递给 create_script()，或写入文件。

运行该示例，我们可能会看到类似以下内容：

{% highlight bash %}
Traceback (most recent call last):
  File "/home/oleavr/src/explore.py", line 4, in <module>
    bundle = compiler.build("agent.ts")
  File "/home/oleavr/.local/lib/python3.10/site-packages/frida/core.py", line 76, in wrapper
    return f(*args, **kwargs)
  File "/home/oleavr/.local/lib/python3.10/site-packages/frida/core.py", line 1150, in build
    return self._impl.build(entrypoint, **kwargs)
frida.NotSupportedError: compilation failed
{% endhighlight %}

这让我们想知道 *为什么* 它失败了，所以让我们为 *diagnostics* 信号添加一个处理程序：

{% highlight python %}
import frida

def on_diagnostics(diag):
    print("on_diagnostics:", diag)

compiler = frida.Compiler()
compiler.on("diagnostics", on_diagnostics)
bundle = compiler.build("agent.ts")
{% endhighlight %}

突然之间一切都变得有意义了：

{% highlight bash %}
on_diagnostics: [{'category': 'error', 'code': 6053,
    'text': "File '/home/oleavr/src/agent.ts' not "
            "found.\n  The file is in the program "
            "because:\n    Root file specified for"
             " compilation"}]
…
{% endhighlight %}

我们忘了实际创建文件！好的，让我们创建 *agent.ts*：

{% highlight js %}
console.log("Hello from Frida:", Frida.version);
{% endhighlight %}

让我们也将该脚本写入文件：

{% highlight python %}
import frida

def on_diagnostics(diag):
    print("on_diagnostics:", diag)

compiler = frida.Compiler()
compiler.on("diagnostics", on_diagnostics)
bundle = compiler.build("agent.ts")
with open("_agent.js", "w", newline="\n") as f:
    f.write(bundle)
{% endhighlight %}

如果我们现在运行它，我们应该有一个准备好的 _agent.js：

{% highlight bash %}
$ cat _agent.js
📦
175 /explore.js.map
39 /explore.js
✄
{"version":3,"file":"explore.js","sourceRoot":"/home/oleavr/src/","sources":["explore.ts"],"names":[],"mappings":"AAAA,OAAO,CAAC,GAAG,CAAC,SAAS,KAAK,CAAC,OAAO,GAAG,CAAC,CAAC"}
✄
console.log(`Hello ${Frida.version}!`);
{% endhighlight %}

这种看起来很奇怪的格式是 GumJS 允许我们选择加入新的 ECMAScript 模块 (ESM) 格式的方式，其中代码被限制在其所属的模块中，而不是在全局范围内进行评估。这也意味着我们可以加载导入/导出值的多个模块。.map 文件是可选的，可以省略，但如果保留，它们允许 GumJS 将生成的 JavaScript 行号映射回堆栈跟踪中的 TypeScript。

无论如何，让我们试用一下 _agent.js：

{% highlight bash %}
$ frida -p 0 -l _agent.js
     ____
    / _  |   Frida 15.2.0 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://frida.re/docs/home/
   . . . .
   . . . .   Connected to Local System (id=local)
Attaching...
Hello 15.2.0!
[Local::SystemSession ]->
{% endhighlight %}

它有效！现在让我们尝试重构它以将代码拆分为两个文件：

### agent.ts

{% highlight typescript %}
import { log } from "./log.js";

log("Hello from Frida:", Frida.version);
{% endhighlight %}

### log.ts

{% highlight typescript %}
export function log(...args: any[]) {
    console.log(...args);
}
{% endhighlight %}

如果我们现在再次运行我们的示例编译器脚本，它应该生成一个看起来稍微有趣一点的 _agent.js：

{% highlight bash %}
📦
204 /agent.js.map
72 /agent.js
199 /log.js.map
58 /log.js
✄
{"version":3,"file":"agent.js","sourceRoot":"/home/oleavr/src/","sources":["agent.ts"],"names":[],"mappings":"AAAA,OAAO,EAAE,GAAG,EAAE,MAAM,UAAU,CAAC;AAE/B,GAAG,CAAC,mBAAmB,EAAE,KAAK,CAAC,OAAO,CAAC,CAAC"}
✄
import { log } from "./log.js";
log("Hello from Frida:", Frida.version);
✄
{"version":3,"file":"log.js","sourceRoot":"/home/oleavr/src/","sources":["log.ts"],"names":[],"mappings":"AAAA,MAAM,UAAU,GAAG,CAAC,GAAG,IAAW;IAC9B,OAAO,CAAC,GAAG,CAAC,GAAG,IAAI,CAAC,CAAC;AACzB,CAAC"}
✄
export function log(...args) {
    console.log(...args);
}
{% endhighlight %}

将其加载到 REPL 中应该会产生与以前完全相同的结果。

## watch()

让我们将我们的玩具编译器变成一个工具，它可以加载编译后的脚本，并在磁盘上的源文件更改时重新编译：

{% highlight python %}
import frida
import sys

session = frida.attach(0)
script = None

def on_output(bundle):
    global script
    if script is not None:
        print("Unloading old bundle...")
        script.unload()
        script = None
    print("Loading bundle...")
    script = session.create_script(bundle)
    script.on("message", on_message)
    script.load()

def on_diagnostics(diag):
    print("on_diagnostics:", diag)

def on_message(message, data):
    print("on_message:", message)

compiler = frida.Compiler()
compiler.on("output", on_output)
compiler.on("diagnostics", on_diagnostics)
compiler.watch("agent.ts")

sys.stdin.read()
{% endhighlight %}

我们出发了：

{% highlight bash %}
$ python3 explore.py
Loading bundle...
Hello from Frida: 15.2.0
{% endhighlight %}

如果我们让它继续运行，然后在磁盘上编辑源代码，我们应该会看到一些新的输出：

{% highlight bash %}
Unloading old bundle...
Loading bundle...
Hello from Frida version: 15.2.0
{% endhighlight %}

耶！

## frida-compile

我们还可以使用 frida-tools 新的 frida-compile CLI 工具：

{% highlight bash %}
$ frida-compile agent.ts -o _agent.js
{% endhighlight %}

它还支持监视模式：

{% highlight bash %}
$ frida-compile agent.ts -o _agent.js -w
{% endhighlight %}

## REPL

我们的 REPL 也由新的 frida.Compiler 提供支持：

{% highlight bash %}
$ frida -p 0 -l agent.ts
     ____
    / _  |   Frida 15.2.0 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://frida.re/docs/home/
   . . . .
   . . . .   Connected to Local System (id=local)
Compiled agent.ts (1428 ms)
Hello from Frida version: 15.2.0
[Local::SystemSession ]->
{% endhighlight %}

## 致谢

感谢 [@hsorbo][] 进行有趣且富有成效的结对编程会议，我们在那里一起开发 frida.Compiler！🙌

## EOF

此版本中还有很多其他好东西，所以一定要查看下面的变更日志。

享受吧！

### 变更日志

- core: 添加 Compiler API。目前仅由 Python 绑定公开，但可从 C/Vala 获得。
- interceptor: 改进 *replace()* 以支持返回原始值。感谢 [@aviramha][]！
- gumjs: 修复 writer 选项中 *pc* 的类型。
- gumjs: 修复具有循环依赖项的 V8 ESM 崩溃。
- gumjs: 处理每个模块具有多个别名的 ESM 包。
- gumjs: 收紧 *Checksum* 数据参数解析。
- android: 修复崩溃传递中的空指针解引用。感谢 [@muhzii][]！
- fruity: 使用环境变量查找 usbmuxd。感谢 [@0x3c3e][]！
- ios: 使 Substrate 检测逻辑更具弹性。感谢 [@lemon4ex][]！
- meson: 仅在可用时尝试使用 V8。感谢 [@muhzii][]！
- windows: 添加对不带 V8 构建的支持。
- devkit: 修复 Windows 上的库依赖提示。感谢 [@nblog][]！


[frida-remote-stream]: https://github.com/nowsecure/frida-remote-stream
[Rollup]: https://rollupjs.org/guide/en/
[@frida/rollup-plugin-node-polyfills]: https://www.npmjs.com/package/@frida/rollup-plugin-node-polyfills
[@rollup/plugin-typescript]: https://www.npmjs.com/package/@rollup/plugin-typescript
[frida-compile]: https://www.npmjs.com/package/frida-compile
[frida-agent-example]: https://github.com/oleavr/frida-agent-example
[@hsorbo]: https://twitter.com/hsorbo
[@aviramha]: https://github.com/aviramha
[@muhzii]: https://github.com/muhzii
[@0x3c3e]: https://github.com/0x3c3e
[@lemon4ex]: https://github.com/lemon4ex
[@nblog]: https://github.com/nblog
