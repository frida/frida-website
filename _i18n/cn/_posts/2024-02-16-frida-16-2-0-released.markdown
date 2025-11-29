---
layout: news_item
title: 'Frida 16.2.0 发布'
date: 2024-02-16 13:45:43 +0100
author: oleavr
version: 16.2.0
categories: [release]
---

这次有很多令人兴奋的新事物。让我们直接潜入。

## 线程名称

Process.enumerateThreads() API 现在还在可用时公开线程名称：

{% highlight sh %}
$ frida -U -F
[Pixel 6 Pro::com.google.android.calculator ]-> Process.enumerateThreads()[1]
{
    "id": 9579,
    "name": "Signal Catcher",
    "state": "waiting",
    "context": { … }
}
[Pixel 6 Pro::com.google.android.calculator ]->
{% endhighlight %}

感谢 [@Hexploitable][] 提供了让这个球滚动起来的很棒的 pull-request 🙌

## 内存保护查询

有时必须快速确定内存中页面的当前保护。感谢 [@mrmacete][]，现在您可以：

{% highlight sh %}
$ frida -p 0
[Local::SystemSession ]-> Memory.queryProtection(Module.getExportByName(null, 'open'))
"r-x"
[Local::SystemSession ]->
{% endhighlight %}

## QuickJS 2024-01-13

此版本还包含上个月发布的最新 QuickJS。这意味着几乎完全支持 ES2023，甚至还有即将推出的 ES2024 规范中的一些功能。另外，还有相当多的错误修复。值得一提的是，现在支持顶级 await，这使得编写在我们的两个 JavaScript 运行时上都能工作的可移植脚本变得更加容易。

## 隐身 (Cloaking)

Frida 跟踪自己的内存范围、线程等，以防止您在进程内省期间看到自己。诸如 Process.enumerateThreads() 之类的内省 API 确保 Frida 自己的资源被隐藏，并且事情看起来就像您不在被插桩的进程中一样。

对于那些使用 Stalker 或其他将您暴露给原始内存位置的人来说，您可能会看到不属于任何加载模块的代码，并想知道它来自哪里。例如，如果您使用 Stalker.follow() 跟踪执行进入或离开 hook 函数，它将执行 Interceptor 生成的一些 Trampoline (蹦床) 代码。

使用 Gum C API 的代理已经可以查询给定的内存地址、线程等是否归 Frida 所有，但这尚未暴露给我们的 JavaScript 绑定。但是现在，感谢 [@mrmacete][] 的另一个很棒的贡献，现在支持这一点。例如：

{% highlight sh %}
$ frida -p 0
[Local::SystemSession ]-> open = Module.getExportByName(null, 'open')
"0x7f929a325840"
[Local::SystemSession ]-> Interceptor.attach(open, () => {})
{}
[Local::SystemSession ]-> Instruction.parse(open).toString()
"jmp 0x7f928940c408"
[Local::SystemSession ]-> Cloak.hasRangeContaining(ptr('0x7f928940c408'))
true
[Local::SystemSession ]-> pointInsideOpen = open.add(16)
"0x7f929a325850"
[Local::SystemSession ]-> Instruction.parse(pointInsideOpen).toString()
"push rbx"
[Local::SystemSession ]-> Cloak.hasRangeContaining(pointInsideOpen)
false
[Local::SystemSession ]->
{% endhighlight %}

## Fast Interceptor (快速拦截器)

一个鲜为人知且相当新的功能，现在也可以从 JavaScript 获得，即 Interceptor.replaceFast()。它的不同之处在于目标被修改为直接向量到您的替换，这意味着与 Interceptor.replace() 相比开销更小。这也意味着如果您想调用原始实现，则需要使用返回的指针。也不可能将其与同一目标的 Interceptor.attach() 结合使用。但是，如果您正在处理热门目标，这绝对是您希望在工具箱中拥有的东西，尤其是与 CModule 结合使用时。

## ELF 导出回归

我们很晚才发现 Frida 16.1.0 破坏了一些 ELF 二进制文件上的 Module#enumerateExports()，这现在终于修复了。事实证明这是我在使 Gum.ElfModule 成为跨平台 API 时添加的边界检查中的一个错误，当时它获得了对离线用例的支持，例如我们的 Barebone 后端的用例。（我们在那里使用它动态地将 Rust 代码注入 OS 内核和裸机目标。）

## ELF 导入槽

那些在 Apple 平台上使用 Frida 的人可能已经注意到 Module#enumerateImports() 为您提供的导入对象总是有一个 *slot* 属性。您可以使用它的一种方法是将新指针写入该地址，让您按模块重新绑定导入。如果 Interceptor 无法 hook 函数，或者对于您想要避免内联 hook 的场景，这非常方便。

从这个版本开始，我们现在也在基于 ELF 的平台上提供 *slot* 属性，因此您也可以在 Linux, Android, FreeBSD 和 QNX 上使用此功能。耶！

## Android 稳定性

最近版本的 Android 上的狂热用户可能经历过“软循环”，即 Frida 随机使 Zygote 崩溃并导致一大块用户空间重启。事实证明这是由于运行时在等待线程数降至一时（即等待进程变为单线程）通过轮询 /proc/self/stat 来准备 fork() 造成的。

现在通过减去 Frida 拥有的线程来解决这个问题，我们通过内部使用 Cloak API 来确定这一点，本文前面已经提到过。我们还利用了新的 ELF 导入槽功能，因此我们可以仅为 libart.so 中的调用者 hook read()。在这种情况下，在 libc.so 的 read() 中插入内联 hook 不是一个好主意，因为我们所在的进程可能会将其用于无限期阻塞的阻塞读取。当想要卸载并卡在等待回滚我们的内联 hook 的机会时，这成为一个挑战。

无论如何，这是一个非常有趣的错误。感谢 [@enovella_][] 报告并帮助追踪此问题 🙌

在谈论 Android 时，此版本还改进了 Android 14 上的 Java hook，其中在 *--enable-optimizations* 的情况下使用了新的 ART 快速入口点。感谢 [@cr4zyserb][] 的这一巧妙贡献。

## 更好的 iOS 16 支持

如果您在尝试在 iOS 上安装 Frida 时遇到 `Service cannot load in requested session`，这现在终于修复了。感谢 [@as0ler][] 协助修复此问题。

## 越狱 tvOS

另一个令人兴奋的发展是我们现在支持越狱的 tvOS，您可以直接从我们的 repo https://build.frida.re/ 获取 .deb。特别感谢 [@tmm1][] 提供了实现此目的的 pull-request。

## 杂项

此版本还有更多内容。其余更改如下：

- symbolutil-libdwarf: 修复 DWARF 5 中 *DW_AT_ranges* 的处理。这意味着 DebugSymbol API 在由较新工具链构建的二进制文件上可以正常工作。
- elf-module: 修复在线时的重定位地址。
- interceptor: 在 arm64 上声明 graft 时检查模块前缀，以兼容 Xcode 的新 libLogRedirect.dylib 在 iOS 17 上的插入。感谢 [@mrmacete][]！
- interceptor: 在 arm64 上隐藏 thunk。感谢 [@mrmacete][]！
- windows: 确保 MSVC 源字符集设置为 UTF-8，以便可以在运行时正确解析嵌入的 JavaScript。感谢 [@Qfrost911][]！
- freebsd: 改进 allocate-near 策略。
- gumjs: 堵塞 QJS load() w/ ESM 期间的泄漏。
- objc: 确保块结构在实现设置器中是可写的。感谢 [@mrmacete][]！
- compiler: 升级 @types/frida-gum 到 18.6.0。

享受吧！


[@Hexploitable]: https://twitter.com/Hexploitable
[@mrmacete]: https://twitter.com/bezjaje
[@enovella_]: https://twitter.com/enovella_
[@cr4zyserb]: https://github.com/cr4zyserb
[@as0ler]: https://twitter.com/as0ler
[@tmm1]: https://twitter.com/tmm1
[@Qfrost911]: https://github.com/Qfrost911
