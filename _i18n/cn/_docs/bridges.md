从 Frida 17.0.0 开始，桥接器不再与 Frida 的 GumJS 运行时捆绑在一起。您可以在 [release notes][] 中阅读更多相关信息。这意味着用户现在必须显式引入他们想要使用的桥接器。不过，Frida REPL 和 `frida-trace` 确实捆绑了所有三个桥接器，以便与现有脚本兼容。

## 目录

1. **REPL 和 frida-trace**
    1. [使用纯 JavaScript](#使用纯-javascript)
    1. [REPL 自动编译](#repl-自动编译)
    1. [使用 frida-compile 手动编译](#使用-frida-compile-手动编译)
1. **使用 API**
    1. [Python 示例](#python-示例)
    1. [Go 示例](#go-示例)

## REPL 和 frida-trace

我们将使用一个简单的脚本将 `ObjC.available` 打印到屏幕上。

{% highlight javascript %}
// script.js
console.log(ObjC.available);
{% endhighlight %}

### 使用纯 JavaScript

这与以前完全一样，因为 REPL 和 frida-trace 捆绑了所有三个桥接器。

{% highlight bash %}
$ frida -p0 -l script.js
     ____
    / _  |   Frida 17.0.5 - A world-class dynamic instrumentation toolkit
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
true
[Local::SystemSession ]->
{% endhighlight %}

### REPL 自动编译

REPL 也可以使用 `.ts` 文件：在空目录中使用 `frida-create -t agent` 来设置所需的脚手架。

### 使用 frida-compile 手动编译

您需要通过在脚本中添加行来指定要使用的桥接器（ObjC, Java, Swift）：

* `import ObjC from "frida-objc-bridge";` - 用于 ObjC
* `import Swift from "frida-swift-bridge";` - 用于 Swift
* `import Java from "frida-java-bridge";` - 用于 Java

我们将重新创建上面的示例，其中我们使用纯 JavaScript 打印 `ObjC.available`。

{% highlight typescript %}
// script.ts
import ObjC from "frida-objc-bridge";

console.log(ObjC.available);
{% endhighlight %}

在空目录中初始化并安装必要的包：

{% highlight bash %}
$ frida-create -t agent
$ npm install
$ npm install frida-objc-bridge
{% endhighlight %}

然后编译代理并加载它：

{% highlight bash %}
$ frida-compile script.ts -o _agent.js -S -c
$ frida -p0 -l _agent.js
     ____
    / _  |   Frida 17.0.5 - A world-class dynamic instrumentation toolkit
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
true
[Local::SystemSession ]->
{% endhighlight %}

## 使用 API

使用绑定提供的 API 需要几个步骤，即：

* 编写脚本
* 运行 `frida-create -t agent`
* 安装您想要的桥接器，例如 `frida-objc-bridge`
* 编写代码来编译脚本并将其加载到进程中

### Python 示例

{% highlight python %}
import frida

def on_diagnostics(diag):
    print("diag", diag)

def on_message(message, data):
    print(message)

compiler = frida.Compiler()
compiler.on("diagnostics", on_diagnostics)
# script is located in /tmp, so we set project root to /tmp
bundle = compiler.build("script.ts", project_root="/tmp")

session = frida.attach(0)

script = session.create_script(bundle)

script.on("message", on_message)
script.load()
{% endhighlight %}

### Go 示例

{% highlight go %}
package main

import (
	"bufio"
	"fmt"
	"github.com/frida/frida-go/frida"
	"os"
)

func main() {
	comp := frida.NewCompiler()
	comp.On("diagnostics", func(diag string) {
		fmt.Printf("Diagnostics: %s\n", diag)
	})

	bopts := frida.NewCompilerOptions()
	bopts.SetProjectRoot("/tmp")
	bopts.SetSourceMaps(frida.SourceMapsOmitted)
	bopts.SetJSCompression(frida.JSCompressionTerser)

	bundle, err := comp.Build("script.ts", bopts)
	if err != nil {
		panic(err)
	}

	session, err := frida.Attach(0)
	if err != nil {
		panic(err)
	}

	script, err := session.CreateScript(bundle)
	if err != nil {
		panic(err)
	}

	script.On("message", func(message string, data []byte) {
		fmt.Printf("%s\n", message)
	})

	script.Load()

	r := bufio.NewReader(os.Stdin)
	r.ReadLine()
}
{% endhighlight %}

[release notes]: /news/2025/05/17/frida-17-0-0-released/
