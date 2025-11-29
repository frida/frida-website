在本教程中，我们将展示如何在目标进程之间发送和接收消息。

## 设置实验

创建一个文件 `hello.c`：

{% highlight c %}
#include <stdio.h>
#include <unistd.h>

void
f (int n)
{
  printf ("Number: %d\n", n);
}

int
main (int argc,
      char * argv[])
{
  int i = 0;

  printf ("f() is at %p\n", f);

  while (1)
  {
    f (i++);
    sleep (1);
  }
}
{% endhighlight %}

使用以下命令编译：

{% highlight bash %}
$ gcc -Wall hello.c -o hello
{% endhighlight %}

启动程序并记下 `f()` 的地址（在以下示例中为 `0x400544`）：

{% highlight bash %}
f() is at 0x400544
Number: 0
Number: 1
Number: 2
…
{% endhighlight %}

## 从目标进程发送消息

以下脚本展示了如何将消息发送回 Python 进程。您可以发送任何可序列化为 JSON 的 JavaScript 值。

创建一个包含以下内容的 `send.py` 文件：

{% highlight py %}
import frida
import sys

session = frida.attach("hello")
script = session.create_script("send(1337);")
def on_message(message, data):
    print(message)
script.on('message', on_message)
script.load()
sys.stdin.read()
{% endhighlight %}

当您运行此脚本时：

{% highlight bash %}
$ python send.py
{% endhighlight %}

它应该打印以下消息：

{% highlight py %}
{'type': 'send', 'payload': 1337}
{% endhighlight %}

这意味着 JavaScript 代码 `send(1337)` 已在 `hello` 进程内执行。使用 `Ctrl-D` 终止脚本。

### 处理来自 JavaScript 的运行时错误

如果 JavaScript 脚本抛出未捕获的异常，这将被传播从目标进程到 Python 脚本。如果您将 `send(1337)` 替换为 `send(a)`（一个未定义的变量），Python 将收到以下消息：

{% highlight py %}
{'type': 'error', 'description': 'ReferenceError: a is not defined', 'lineNumber': 1}
{% endhighlight %}

注意 `type` 字段（`error` 与 `send`）。

## 在目标进程中接收消息

可以将消息从 Python 脚本发送到 JavaScript 脚本。创建文件 `pingpong.py`：

{% highlight py %}
import frida
import sys

session = frida.attach("hello")
script = session.create_script("""
    recv('poke', function onMessage(pokeMessage) { send('pokeBack'); });
""")
def on_message(message, data):
    print(message)
script.on('message', on_message)
script.load()
script.post({"type": "poke"})
sys.stdin.read()
{% endhighlight %}

运行脚本：

{% highlight bash %}
$ python pingpong.py
{% endhighlight %}

产生输出：

{% highlight py %}
{'type': 'send', 'payload': 'pokeBack'}
{% endhighlight %}

<div class="note info">
  <h5>recv() 的机制</h5>
  <p>
    recv() 方法本身是异步的（非阻塞）。注册的回调（onMessage）将恰好接收一条消息。要接收下一条消息，必须使用 recv() 重新注册回调。
  </p>
</div>

### 目标进程中的阻塞接收

可以在 JavaScript 脚本内等待消息到达（阻塞接收）。创建脚本 `rpc.py`：

{% highlight py %}
import frida
import sys

session = frida.attach("hello")
script = session.create_script("""
Interceptor.attach(ptr("%s"), {
    onEnter(args) {
        send(args[0].toString());
        const op = recv('input', value => {
            args[0] = ptr(value.payload);
        });
        op.wait();
    }
});
""" % int(sys.argv[1], 16))
def on_message(message, data):
    print(message)
    val = int(message['payload'], 16)
    script.post({'type': 'input', 'payload': str(val * 2)})
script.on('message', on_message)
script.load()
sys.stdin.read()
{% endhighlight %}

程序 `hello` 应该正在运行，并且您应该记下在其开头打印的地址（例如 `0x400544`）。运行：

{% highlight bash %}
$ python rpc.py 0x400544
{% endhighlight %}

然后观察运行 `hello` 的终端中的变化：

{% highlight bash %}
Number: 3
Number: 8
Number: 10
Number: 12
Number: 14
Number: 16
Number: 18
Number: 20
Number: 22
Number: 24
Number: 26
Number: 14
{% endhighlight %}

`hello` 程序应该开始写入“加倍”的值，直到您停止 Python 脚本（`Ctrl-D`）。
