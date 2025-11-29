---
layout: news_item
title: 'Frida 2.0.0 发布'
date: 2015-03-01 01:00:00 +0100
author: oleavr
version: 2.0.0
categories: [release]
---

是时候发布一个令人兴奋的新版本了！主要变化包括：

- Mac 和 iOS 上不再有内核恐慌！阅读完整故事 [here](https://medium.com/@oleavr/diy-kernel-panic-os-x-and-ios-in-10-loc-c250d9649159)。
- Mac 和 iOS 注入器执行 Frida dylib 的手动映射。这意味着我们能够附加到受到严格沙盒保护的进程。
- 像 *frida-trace*、*frida-repl* 等 CLI 工具对生成进程有了全新的支持：
{% highlight bash %}
$ frida-trace -i 'open*' -i 'read*' /bin/cat /etc/resolv.conf
    27 ms	open$NOCANCEL()
    28 ms	read$NOCANCEL()
    28 ms	read$NOCANCEL()
    28 ms	read$NOCANCEL()
Target process terminated.
Stopping...
$
{% endhighlight %}
- *frida-repl* 和 *frida-discover* 中的可用性改进。
- 第一次调用 `DeviceManager.enumerate_devices()` 做得更好，并且还为您提供当前连接的 iOS 设备，因此对于简单的应用程序或脚本，如果您要求设备已经存在，您不再需要订阅更新。
- python API 现在为您提供 `frida.get_usb_device(timeout = 0)` 和 `frida.get_remote_device()` 以便轻松访问 iOS 和远程/Android 设备。
- 传递给 `Interceptor.attach()` 的 `onEnter` 和 `onLeave` 回调可以访问 `this.registers` 以检查 CPU 寄存器，这在处理自定义调用约定时非常有用。
- `console.log()` 记录到应用程序侧的控制台而不是目标进程。这个变化实际上是我们不得不为此版本提升主要版本的原因。
- Android 5.0 兼容性，模 ART 支持。
- 对 Android/x86 的全新支持。除了 Dalvik 集成外，一切正常；如果您想通过拉取请求帮助解决此问题，请联系我们！

想帮忙吗？看看我们的 [GSoC 2015 Ideas Page](/docs/gsoc-ideas-2015/) 以了解我们下一步想去哪里。

享受吧！

**凌晨 2 点更新：** 一个 iOS 问题在最终测试中遗漏了，所以我们刚刚推送了 2.0.1 来解决这个问题。

**晚上 11 点更新：** 感谢您的出色反馈，我们在具有某些 iOS 设备配置的 Windows 上使用 Frida 时发现了一个严重错误。请升级到 2.0.2，如果您遇到任何问题，请告诉我们。
