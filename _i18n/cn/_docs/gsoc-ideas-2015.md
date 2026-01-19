## 让 Android 成为 Frida 的一等公民

### 2015 年更新：感谢 [NowSecure][]，这现在已在 Frida 中实现。

**简要说明：** 虽然 Frida 目前确实支持 Android，但有两个缺失的部分导致在插桩 Android 应用程序时产生大量摩擦，我们需要改进这些方面：

- 打包：打包 frida-server 并将其作为系统守护程序运行或捆绑启动器应用程序。

- 集成：添加一个 Android 后端，用于自动化 USB 设备发现和端口转发。这类似于 Frida 的 iOS «Fruity» 后端，它与 iTunes 的 usbmuxd 集成，有效地自动化设备发现和 TCP 端口转发，因此用户只需插入设备并在几秒钟内开始插桩移动应用程序。
在实现方面，这应该是关于与 adb 集成，或者嵌入 adb 的核心，这将：
  - 枚举连接的 Android 设备并在发生热插拔事件时通知应用程序。
  - 根据需要自动转发端口；不再需要在用户每次附加到新进程时都进行容易出错的 `adb forward`。

**预期结果：** Android 包。设备发现和自动端口转发。

**知识先决条件：** Vala, C

**可能的导师：** Ole André Vadla Ravnås &lt;[oleavr@gmail.com](mailto:oleavr@gmail.com)&gt;, Karl Trygve Kalleberg &lt;[karltk@gmail.com](mailto:karltk@gmail.com)&gt;


## 添加对在 ART VM 中运行的 Android 应用程序的支持

**简要说明：** Frida 目前支持 Dalvik，虽然大部分代码只是与 VM 实现的 JNI API 交互，但有一些部分是特定于 VM 的。当前代码可以在 [此处](https://github.com/frida/frida-gum/blob/42b69917976f43ba3ec4297046b319970dc037dd/gum/gumscript-runtime-dalvik.js) 找到。
添加对 ART VM 的支持应该只是改进该实现以添加特定于 ART 的部分，然后公开一个统一的 API。当前的 `Dalvik` 模块将只是一个已弃用的别名，保留到下一个主要的 Frida 版本。

**预期结果：** ART VM 支持。

**知识先决条件：** JavaScript, C

**可能的导师：** Ole André Vadla Ravnås &lt;[oleavr@gmail.com](mailto:oleavr@gmail.com)&gt;, Karl Trygve Kalleberg &lt;[karltk@gmail.com](mailto:karltk@gmail.com)&gt;


## 将 Stalker 移植到 ARM

**简要说明：** Frida 的 Stalker 是一个基于动态重新编译的非常强大的代码跟踪引擎。它目前仅适用于 x86。将其移植到 ARM 将允许 [CryptoShark](https://github.com/frida/cryptoshark) 用于移动应用程序。

想了解更多关于它是如何为 x86 实现的吗？在 [此处](https://medium.com/@oleavr/anatomy-of-a-code-tracer-b081aadb0df8) 阅读更多内容。

**预期结果：** Stalker 能够在 ARM 上跟踪代码。

**知识先决条件：** C, Assembly

**可能的导师：** Ole André Vadla Ravnås &lt;[oleavr@gmail.com](mailto:oleavr@gmail.com)&gt;, Karl Trygve Kalleberg &lt;[karltk@gmail.com](mailto:karltk@gmail.com)&gt;


## 将 Stalker 移植到 ARM64

**简要说明：** Frida 的 Stalker 是一个基于动态重新编译的非常强大的代码跟踪引擎。它目前仅适用于 x86。将其移植到 ARM64 将允许 [CryptoShark](https://github.com/frida/cryptoshark) 用于移动应用程序。

想了解更多关于它是如何为 x86 实现的吗？在 [此处](https://medium.com/@oleavr/anatomy-of-a-code-tracer-b081aadb0df8) 阅读更多内容。

**预期结果：** Stalker 能够在 ARM64 上跟踪代码。

**知识先决条件：** C, Assembly

**可能的导师：** Ole André Vadla Ravnås &lt;[oleavr@gmail.com](mailto:oleavr@gmail.com)&gt;, Karl Trygve Kalleberg &lt;[karltk@gmail.com](mailto:karltk@gmail.com)&gt;


## 添加对在 Android 上 spawn 应用程序的支持：从第一条指令开始插桩

### 2015 年更新：感谢 [NowSecure][]，这现在已在 Frida 中实现。

**简要说明：** 不要与 Frida 中已经存在的 spawn 进程的支持混淆，这是关于添加对从 Zygote fork 自身以运行应用程序后执行的第一条指令开始插桩 Android 应用程序的支持。

**预期结果：** 用于 spawn Android 应用程序的 API。

**知识先决条件：** Vala, C

**可能的导师：** Ole André Vadla Ravnås &lt;[oleavr@gmail.com](mailto:oleavr@gmail.com)&gt;, Karl Trygve Kalleberg &lt;[karltk@gmail.com](mailto:karltk@gmail.com)&gt;


## 为主要发行版打包

**简要说明：** 我们应该让 Linux 用户更容易上手，并通过尽可能多地出现在生态系统中来提高 Frida 的知名度。

**预期结果：** Frida 的 buildbot 自动发布主要发行版的软件包。

**知识先决条件：** python

**可能的导师：** Ole André Vadla Ravnås &lt;[oleavr@gmail.com](mailto:oleavr@gmail.com)&gt;, Karl Trygve Kalleberg &lt;[karltk@gmail.com](mailto:karltk@gmail.com)&gt;


## 将 Frida 移植到 Windows Phone

**简要说明：** Frida 目前支持 Windows、macOS、Linux、iOS、Android 和 QNX，但遗憾的是尚不支持 Windows Phone。添加对 WP 的支持将需要：

- 一个注入器，用于将 Frida 的共享库注入到目标进程中

- 进程 spawn 支持

- 与 CLR 运行时动态交互的 JavaScript 运行时，类似于 Frida 的 JS 环境中内置的 [Dalvik JS 运行时](https://github.com/frida/frida-gum/blob/42b69917976f43ba3ec4297046b319970dc037dd/gum/gumscript-runtime-dalvik.js)。

前两项可能类似于当前的 Windows 后端，尽管可能要简单得多。

**预期结果：** 支持插桩 Windows Phone 应用程序。

**知识先决条件：** JavaScript, C, CLR

**可能的导师：** Ole André Vadla Ravnås &lt;[oleavr@gmail.com](mailto:oleavr@gmail.com)&gt;, Karl Trygve Kalleberg &lt;[karltk@gmail.com](mailto:karltk@gmail.com)&gt;


## 向 JavaScript 暴露回溯器和符号解析 API

### 2015 年更新：感谢 [NowSecure][]，这现在已在 Frida 中实现。

**简要说明：** frida-gum 中目前有 [Backtracer](https://github.com/frida/frida-gum/blob/42b69917976f43ba3ec4297046b319970dc037dd/gum/gumbacktracer.h) 和 [符号解析](https://github.com/frida/frida-gum/blob/42b69917976f43ba3ec4297046b319970dc037dd/gum/gumsymbolutil.h) API，尚未暴露给 JS 运行时。

然而，符号解析 API 不仅仅是暴露此 API 的问题，因为底层实现将需要一些调整才能在注入到另一个进程时正常工作。Windows 实现目前依赖于加载 DbgHelp.dll，这可能不是一个可接受的约束。

**预期结果：** JavaScript 运行时中可用的回溯器和符号解析 API。

**知识先决条件：** JavaScript, C

**可能的导师：** Ole André Vadla Ravnås &lt;[oleavr@gmail.com](mailto:oleavr@gmail.com)&gt;, Karl Trygve Kalleberg &lt;[karltk@gmail.com](mailto:karltk@gmail.com)&gt;


[NowSecure]: https://www.nowsecure.com/
