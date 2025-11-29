---
layout: news_item
title: 'Frida 1.0.7 发布'
date: 2014-01-12 23:00:00 +0100
author: oleavr
version: 1.0.7
categories: [release]
---

此版本在命令行工具中带来了 USB 设备支持，并添加了 `frida-ps` 用于枚举本地和远程进程。

例如，要枚举系留 iOS 设备上的进程：
{% highlight bash %}
$ frida-ps -U
{% endhighlight %}

`frida-trace` 和 `frida-discover` 也接受 `-U` 开关。

关于如何在您的 iOS 设备上设置此功能的文档将很快添加到网站上。

然而，这并不是最令人兴奋的部分。从这个版本开始，Frida 获得了自 HN 发布以来的第一个贡献。[Pete Morici](https://github.com/pmorici) 潜入并贡献了对在 `frida-trace` 中指定模块相对函数的支持：

{% highlight bash %}
$ frida-trace -a 'kernel32.dll+0x1234'
{% endhighlight %}

享受吧！
