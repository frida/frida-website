---
layout: news_item
title: 'Frida 1.6.1 发布'
date: 2014-07-26 19:00:00 +0100
author: oleavr
version: 1.6.1
categories: [release]
---

是时候发布错误修复版本了。亮点：

- 与 ARM64 上的 Pangu iOS 越狱兼容。问题在于 RWX 页面不像以前使用 evad3rs 越狱那样可用。
- 修复分离时偶尔的目标进程崩溃。
- 修复在第一次建立失败后第二次尝试附加到进程时的崩溃。这主要影响 Android 用户，但在使用 `frida-server` 时可能会发生在任何操作系统上。
- 在 Linux/x86-64 和 Android/ARM 上更快更可靠的注入。
- 修复阻止在 Windows 上 hook HeapFree 和朋友的问题。
- 升级 GLib、libgee、json-glib 和 Vala 依赖项以提高性能和错误修复。
- 不再有资源泄漏。如果您发现任何问题，请报告。

此外，自 1.6.0 以来，正如我的 [blog post][] 中所涵盖的那样，现在有一个功能齐全的 [binding for Qml][]。这对于那些构建图形跨平台工具的人来说应该很有趣。

[blog post]: https://medium.com/@oleavr/build-a-debugger-in-5-minutes-1-5-51dce98c3544
[binding for Qml]: https://github.com/frida/frida-qml
