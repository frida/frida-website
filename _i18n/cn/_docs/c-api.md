## 入门

为您提供用于注入、函数操作、内存读取等的 JavaScript API 的功能也可从 C 获得。

Frida 分为几个模块，我们将在下面讨论。

这些模块都可以单独编译，也可以在 [releases 页面](https://github.com/frida/frida/releases)上找到。

devkit 下载附带了如何使用每个模块的示例。使用 devkit 是学习如何利用每个模块的最佳方式。

## core

frida-core 包含主要的注入代码。通过 frida-core，您可以注入进程、创建运行 QuickJS 的线程并运行您的 JavaScript。

有关源代码，请参阅 [frida-core](https://github.com/frida/frida-core) 仓库。

## gum

frida-gum 允许您使用 C 增强和替换函数。

devkit 中的示例向您展示了如何仅使用 C 增强 `open` 和 `close`。

有关源代码，请参阅 [frida-gum](https://github.com/frida/frida-gum) 仓库。

## gumjs

frida-gumjs 包含 JavaScript 绑定。

## gadget

类似于 frida-agent，除了通过 DYLD_INSERT_LIBRARIES 注入、与应用程序捆绑等，它可以在远程模式下运行，在该模式下它监听并且看起来就像 frida-server。

_请点击上面的“Improve this page”并添加示例。谢谢！_
