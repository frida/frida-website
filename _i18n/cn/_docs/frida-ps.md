这是一个用于列出进程的命令行工具，在与远程系统交互时非常有用。

您可以从 [frida-ls-devices](/docs/frida-ls-devices) 工具获取设备 ID。
{% highlight bash %}
# 通过 USB 将 Frida 连接到 iPad 并列出正在运行的进程
$ frida-ps -U

# 列出正在运行的应用程序
$ frida-ps -Ua

# 列出已安装的应用程序
$ frida-ps -Uai

# 将 Frida 连接到特定设备
$ frida-ps -D 0216027d1d6d3a03

{% endhighlight %}
