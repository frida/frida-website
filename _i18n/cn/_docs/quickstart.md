对于不耐烦的人，这里是如何使用 Frida 进行函数跟踪：

{% highlight bash %}
~ $ pip install frida-tools
~ $ frida-trace -i "recv*" -i "read*" twitter
recv: Auto-generated handler: …/recv.js
# (snip)
recvfrom: Auto-generated handler: …/recvfrom.js
Started tracing 21 functions. Press Ctrl+C to stop.
    39 ms	recv()
   112 ms	recvfrom()
   128 ms	recvfrom()
   129 ms	recvfrom()
{% endhighlight %}

如您所见，Frida 将自己注入到 Twitter 中，枚举了加载的共享库，并 hook 了所有名称以 `recv` 或 `read` 开头的函数。它还生成了一些样板脚本，用于在函数调用发生时检查它们。现在，这些脚本只是示例，您可以根据自己的喜好进行编辑，并且当它们在文件系统上更改时会自动重新加载。默认情况下，它们只是打印函数的名称，如上面的输出所示。

现在，让我们看看生成的 `recvfrom.js`：
{% highlight js %}
/*
 * 由 Frida 自动生成。请修改以匹配 recvfrom 的签名。
 *
 * 这个存根有点笨。Frida 的未来版本可以根据 OS API 参考、手册页等自动生成。（欢迎 Pull request！）
 *
 * 有关完整的 API 参考，请参阅：
 * https://frida.re/docs/javascript-api/
 */

{
    /**
     * 在即将调用 recvfrom 时同步调用。
     *
     * @this {object} - 允许您存储要在 onLeave 中使用的状态的对象。
     * @param {function} log - 调用此函数以向用户显示字符串。
     * @param {array} args - 表示为 NativePointer 对象数组的函数参数。
     * 例如，如果第一个参数是指向 UTF-8 编码的 C 字符串的指针，则使用 args[0].readUtf8String()。
     * 也可以通过将 NativePointer 对象分配给此数组的元素来修改参数。
     * @param {object} state - 允许您跨函数调用保持状态的对象。
     * 一次只执行一个 JavaScript 函数，因此不必担心竞争条件。
     * 但是，不要使用它来跨 onEnter/onLeave 存储函数参数，
     * 而是使用 "this"，它是一个用于保持调用本地状态的对象。
     */
    onEnter(log, args, state) {
        log("recvfrom()");
    },

    /**
     * 在即将从 recvfrom 返回时同步调用。
     *
     * 详见 onEnter。
     *
     * @this {object} - 允许您访问 onEnter 中存储的状态的对象。
     * @param {function} log - 调用此函数以向用户显示字符串。
     * @param {NativePointer} retval - 表示为 NativePointer 对象的返回值。
     * @param {object} state - 允许您跨函数调用保持状态的对象。
     */
    onLeave(log, retval, state) {
    }
}
{% endhighlight %}

现在，将 `log()` 行替换为以下内容：
{% highlight js %}
log("recvfrom(socket=" + args[0].toInt32()
    + ", buffer=" + args[1]
    + ", length=" + args[2].toInt32()
    + ", flags=" + args[3]
    + ", address=" + args[4]
    + ", address_len=" + args[5].readPointer().toInt32()
    + ")");
{% endhighlight %}

保存文件（它将自动重新加载）并在您的 Twitter 应用程序中执行一些操作以触发一些网络活动。您现在应该看到类似以下内容：

{% highlight bash %}
  8098 ms	recvfrom(socket=70,
                         buffer=0x32cc018, length=65536,
                         flags=0x0,
                         address=0xb0420bd8, address_len=16)
{% endhighlight %}

不过这不算什么。当您开始使用 Python API 构建自己的工具时，真正的魔法才会发生，[frida-trace][] 就是基于该 API 构建的。

[frida-trace]: https://github.com/frida/frida-tools/blob/main/frida_tools/tracer.py
