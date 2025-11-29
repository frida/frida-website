如果您在安装或使用 Frida 时遇到问题，这里有一些可能有帮助的提示。如果您遇到的问题未在下面涵盖，请[报告问题]({{ site.organization_url }}/frida-website/issues/new)，以便 Frida 社区可以改善每个人的体验。

## ValueError: ambiguous name; it matches:

这意味着您在 `frida.attach()` 中指定的进程名称匹配多个进程。您可以使用 PID 代替：

{% highlight py %}
session = frida.attach(12345)
{% endhighlight %}

## SystemError: attach_to_process PTRACE_ATTACH failed: 1

这（可能）意味着您没有权限附加到目标进程。该进程可能归另一个用户所有，而您不是 root。您可能忘记启用非子进程的 ptrace。尝试：

{% highlight bash %}
sudo sysctl kernel.yama.ptrace_scope=0
{% endhighlight %}

这也可能是[由于 Magisk Hide](https://github.com/frida/frida/issues/824#issuecomment-479664290)。尝试禁用它并在运行命令之前重新启动。

## Failed to spawn: unexpected error while spawning child process 'XXX' (task_for_pid returned '(os/kern) failure')

在 macOS 上，这可能意味着您没有正确签名 Frida 或缺少权限。例如，如果您通过 SSH 运行 Frida，并且无法响应在*正常*使用下会弹出的身份验证对话框。

如果是签名问题，请按照[此过程]({{ site.repository }}#mac-and-ios)操作，否则，尝试：

{% highlight bash %}
**WARNING: This may weaken security**
sudo security authorizationdb write system.privilege.taskport allow
{% endhighlight %}

您可能还必须禁用系统完整性保护（SIP）来插桩系统二进制文件，但是，再次强调，**/!\ 这将削弱安全性 /!\**。

## ImportError: dynamic module does not define init function (init_frida)

当尝试在 python 3.x 中使用为 python 2.x 编译的 `frida-python` 时，或者反之亦然，会出现此错误或其他类似错误消息。检查您正在运行哪个 python 解释器以及使用了哪个 `PYTHONPATH` / `sys.path`。
