---
layout: news_item
title: 'Frida 1.6.3 发布'
date: 2014-08-24 23:00:00 +0100
author: oleavr
version: 1.6.3
categories: [release]
---

这个最新版本包括一系列增强功能和错误修复。一些亮点：

- Frida 内部的其余部分已从 udis86 迁移到 Capstone，这意味着我们的 Stalker 现在能够跟踪具有最新 x86 指令的二进制文件。这项工作的一部分还包括在 Windows 和 Mac 上的 32 位和 64 位二进制文件上对其进行实战测试，所有已知问题现已解决。

- `Memory.protect()` 已添加到 JavaScript API，允许您轻松更改页面保护。例如：

{% highlight js %}
Memory.protect(ptr("0x1234"), 4096, 'rw-');
{% endhighlight %}

- `Process.enumerateThreads()` 省略了 Frida 自己的线程，所以您不必担心它们。

- Python 3 二进制文件现在针对 Python 3.4 构建。

随着这个版本的发布，让我们谈谈 [CryptoShark](https://github.com/frida/cryptoshark)：

<iframe width="560" height="315" src="//www.youtube.com/embed/hzDsxtcRavY?rel=0" frameborder="0" allowfullscreen></iframe>

获取预构建的 Windows 二进制文件 [here](https://build.frida.re/frida/windows/Win32-Release/bin/cryptoshark-0.1.1.exe)，或者如果您想在 Mac 或 Linux 上试用它，请从源代码构建它。

享受吧！
