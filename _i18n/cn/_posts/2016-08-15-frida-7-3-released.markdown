---
layout: news_item
title: 'Frida 7.3 Released'
date: 2016-08-15 23:00:00 +0200
author: oleavr
version: 7.3
categories: [release]
---

终于到了发布时间，这次的重点是提高质量。因为距离我们上次升级第三方依赖项已经有一段时间了，而且我发现自己正在追踪 GLib 中一个已经在上游修复的内存泄漏，我想是时候升级我们的依赖项了。因此，在这个版本中，我很高兴地宣布我们现在打包了最新的 V8、GLib、Vala 编译器等。我们也非常注意消除资源泄漏，因此您可以附加到长时间运行的进程，而不必担心内存分配或操作系统句柄堆积。

最后，让我们总结一下变化：

7.3.0:

- core: 升级到最新的 V8、GLib、Vala、Android NDK 等
- core: 堵塞资源泄漏
- core: 修复 Linux/x86-32 上的线程枚举
- core: (arm64) 通过添加对重定位具有 FP/SIMD 目标寄存器的 LDRPC 的支持来改进函数 hook

7.3.1:

- core: 像以前一样使用 PIE 构建 Android 二进制文件

7.3.2:

- core: 添加 *Script.setGlobalAccessHandler()* 用于处理访问未声明全局变量的尝试，这对于构建 REPL 很有用

7.3.3:

- objc: 当期望对象时将 *Number* 转换为 *NSNumber*
- objc: 添加对自动转换为对象数组的支持，在调用例如 *+[NSArray arrayWithObjects:count:]* 时很有用

7.3.4:

- core: 改进不稳定的访问器 API
- core: 修复 Duktape 全局访问器逻辑，使其仅应用于读取

7.3.5:

- core: 改进 *hexdump()* 以支持任何符合 *NativePointer* 的对象
- objc: 修复 *L* 类型的处理

7.3.6:

- core: 修复 devkit 头文件自动生成逻辑中的回归

享受吧！
