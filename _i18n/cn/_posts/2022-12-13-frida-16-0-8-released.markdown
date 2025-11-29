---
layout: news_item
title: 'Frida 16.0.8 发布'
date: 2022-12-13 00:21:38 +0100
author: oleavr
version: 16.0.8
categories: [release]
---

这次我们专注于完善我们的 macOS 和 iOS 支持。对于那些使用 *spawn()* 和 spawn-gating 进行早期插桩的人来说，情况现在好多了。

## i/macOS spawn() 性能

此版本中最令人兴奋的变化完全是关于性能的。以前使用 Frida 启动时需要一段时间才能启动的程序现在应该启动得更快。这个长期存在的瓶颈非常糟糕，以至于拥有大量库的应用程序可能会因为 Frida 过度减慢其启动速度而无法启动。

## i/macOS 和 SIGPIPE

接下来我们修复了一个长期存在的可靠性问题。事实证明，我们用于 IPC 的文件描述符没有设置 SO_NOSIGPIPE，因此我们有时可能会遇到 Frida 或目标进程突然终止的情况，而另一方在尝试 write() 时最终会被 SIGPIPE 击中。

## 沙盒环境，第二部分

上一版本引入了一些大胆的新更改以支持注入强化目标。从那时起，[@hsorbo][] 和我重新深入研究了我们最近的 GLib kqueue() 补丁并修复了一些粗糙的边缘。我们还修复了一个回归，即通过 usbmuxd 附加到强化进程会失败并显示“连接已关闭”。

## Linux

在 Linux 和 Android 方面，你们中的一些人可能已经注意到线程枚举可能会随机失败，尤其是在繁忙的进程中。这个问题现在终于解决了。

此外，感谢 [@drosseau][]，我们还有一个错误处理改进，应该可以避免在 32-/64-bit 跨架构构建失败时产生一些混淆。

## EOF

这就是这次的全部内容。享受吧！


[@hsorbo]: https://twitter.com/hsorbo
[@drosseau]: https://github.com/drosseau
