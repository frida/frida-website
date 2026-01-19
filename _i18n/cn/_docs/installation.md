安装 Frida 并准备就绪只需要几分钟。如果它变得很麻烦，请[提交 issue]({{ site.organization_url }}/frida-website/issues/new)（或提交 pull request）描述您遇到的问题以及我们如何使该过程更容易。

### Frida CLI 工具的要求

安装 Frida 的 CLI 工具简单直接，但在开始之前，您需要确保您的系统满足一些要求。

- [Python](https://python.org/) – 强烈推荐最新的 3.x 版本
- Windows, macOS, or GNU/Linux

## 使用 pip 安装

安装 Frida CLI 工具的最好方法是通过 [PyPI][]：

{% highlight bash %}
$ pip install frida-tools
{% endhighlight %}

如果您在安装 Frida 时遇到问题，请查看[故障排除][troubleshooting]页面或[报告问题]({{ site.organization_url }}/frida-website/issues/new)，以便 Frida 社区可以为每个人改善体验。

## 手动安装

您也可以从 Frida 的 GitHub [releases][] 页面获取其他二进制文件。

## 测试您的安装

启动一个我们可以注入的进程：

{% highlight bash %}
$ cat
{% endhighlight %}

让它静置并等待输入。在 Windows 上，您可能想使用 `notepad.exe`。

请注意，此示例在 macOS El Capitan 及更高版本上不起作用，因为它拒绝针对系统二进制文件的此类尝试。有关更多详细信息，请参阅[此处]({{ site.repository }}/issues/83)。但是，如果您将 `cat` 二进制文件复制到例如 `/tmp/cat`，然后运行它，则该示例应该可以工作：

{% highlight bash %}
$ cp /bin/cat /tmp/cat
$ /tmp/cat
{% endhighlight %}

在另一个终端中，创建一个包含以下内容的 `example.py` 文件：

{% highlight py %}
import frida

def on_message(message, data):
    print("[on_message] message:", message, "data:", data)

session = frida.attach("cat")

script = session.create_script("""
rpc.exports.enumerateModules = () => {
  return Process.enumerateModules();
};
""")
script.on("message", on_message)
script.load()

print([m["name"] for m in script.exports_sync.enumerate_modules()])
{% endhighlight %}

如果您在 GNU/Linux 上，请执行：

{% highlight bash %}
$ sudo sysctl kernel.yama.ptrace_scope=0
{% endhighlight %}

以启用对非子进程的 ptrace。

此时，我们准备好试用 Frida 了！运行 example.py 脚本并观看奇迹发生：

{% highlight bash %}
$ python example.py
{% endhighlight %}

输出应该类似于此（取决于您的平台和库版本）：

{% highlight py %}
['cat', …, 'ld-2.15.so']
{% endhighlight %}

[PyPI]: https://pypi.python.org/pypi/frida-tools
[troubleshooting]: ../troubleshooting/
[releases]: https://github.com/frida/frida/releases
