---
layout: news_item
title: 'Frida 3.0.0 发布'
date: 2015-03-20 23:00:00 +0100
author: oleavr
version: 3.0.0
categories: [release]
---

您可能想知道：

> 为什么是 Python API，却是 JavaScript 调试逻辑？

好吧，您现在可以这样做：

{% highlight sh %}
$ npm install frida
{% endhighlight %}

我们刚刚为您带来了全新的 [Node.js 绑定](https://github.com/frida/frida-node)，它们是完全异步的：

{% gist 6ecae99945ccba47427a %}

查看 [示例](https://github.com/frida/frida-node/blob/46a5f92203ab86978a2af68d6c926d6d2b63fbe7/examples/interactive.js) 以了解 API 是什么样子的。它几乎是 Python 绑定提供的 API 的 1:1 映射，但遵循 Node.js / JavaScript 约定，如 camelCased 方法名、返回 ES6 *Promise* 对象而不是阻塞的方法等。

现在，将其与 [NW.js](https://github.com/nwjs/nw.js/) 结合使用，您可以完全使用 HTML、CSS 和 JavaScript 构建自己的桌面应用程序。

所以，全新的 Node.js 绑定；太棒了！然而，我们并没有止步于此。但首先，关于未来的一两句话。我很高兴地宣布，我刚刚创办了一家公司，旨在赞助 Frida 的兼职开发。通过提供逆向工程和软件开发专业知识，目标是产生足够的收入来支付我的账单，并留出一些时间来开发 Frida。从长远来看，我希望也会有帮助添加功能或将 Frida 集成到第三方产品的需求。与此同时，如果您认识正在寻找逆向工程或软件开发专业知识的人，如果您能好心地推荐他们与我联系，我将不胜感激。详情请见 [我的简历](https://github.com/oleavr/cv/raw/master/oleavr.pdf)。

撇开这些不谈，让我们回到发布。接下来：32 位 Linux 支持！甚至 *Stalker* 也已被移植。不仅如此，Linux 后端甚至可以像我们在其他平台上一样进行跨架构注入。这意味着 64 位 Frida 进程，例如您的 Python 解释器，可以注入到 32 位进程中。反之亦然。

另一个很棒的更新是 [Tyilo](https://github.com/Tyilo) 为 *frida-trace* 贡献了 [改进](https://github.com/frida/frida-python/commit/daf1a310670588e5672af2205658598be342c2e2)，因此它现在使用手册页自动生成日志处理程序。太棒了，是吧？但还有更多好东西：

- *frida-server* 端口现在被回收，所以如果您在 Android 上使用 Frida，您不必一直转发端口，除非您实际上同时附加到多个进程。
- Linux 和 Android `spawn()` 支持已得到改进，也支持 PIE 二进制文件。
- Android 稳定性和兼容性改进。
- Mac 和 Linux 构建系统已经过改进，可以轻松构建您关心的部分；甚至可能还有一些您甚至不知道存在的组件，以前默认情况下未构建。
- Python 绑定有一个小的简化，所以不再是 `frida.attach(pid).session.create_script()`，而仅仅是 `frida.attach(pid).create_script()`。这就像全新的 Node.js 绑定一样，也是我们不得不提升主要版本的原因。

这就是它的要点。请通过在网络上传播这篇文章来帮助宣传。作为一个开源项目，我们还很小，所以口碑营销对我们来说意义重大。

享受吧！
