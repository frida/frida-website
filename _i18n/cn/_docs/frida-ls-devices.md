这是一个用于列出已连接设备的命令行工具，在与多个设备交互时非常有用。

{% highlight bash %}
# 通过 USB 将 Frida 连接到 iPad 并列出正在运行的进程
$ frida-ls-devices

# 输出示例

Id                                        Type    Name
----------------------------------------  ------  ----------------
local                                     local   Local System
0216027d1d6d3a03                          tether  Samsung SM-G920F
1d07b5f6a7a72552aca8ab0e6b706f3f3958f63e  tether  iOS Device
tcp                                       remote  Local TCP


{% endhighlight %}
