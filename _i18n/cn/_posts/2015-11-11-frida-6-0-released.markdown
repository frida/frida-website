---
layout: news_item
title: 'Frida 6.0 发布'
date: 2015-11-11 19:00:00 +0100
author: oleavr
version: 6.0
categories: [release]
---

这次是史诗般的发布，带来了全新的 iOS 9 支持和各处的改进。有关更多背景信息，请查看我的博客文章 [here](https://www.nowsecure.com/blog/2015/11/16/ios-9-reverse-engineering-with-javascript/) 和 [here](https://www.nowsecure.com/blog/2015/11/23/ios-instrumentation-without-jailbreak/)。

这里有很多内容要涵盖，但摘要基本上是：

6.0.0:

- core: 添加对 OS X El Capitan 的支持
- core: 添加对 iOS 9 的支持
- core: 修复 Cydia 包中的 launchd plist 权限
- core: 暂时在 iOS 上禁用我们的动态链接器
- core: 添加基于 JavaScriptCore 的新 JavaScript 运行时，因为我们无法在当前的越狱中使用 V8 在 iOS 9 上
- core: 当附加到 *pid=0* 时添加全新的系统会话
- core: 改进 arm hook，包括对早期 TBZ/TBNZ/IT/B.cond 的支持，并避免重定位后续指令循环回的指令
- core: 修复 arm64 上 LDR.W 指令的重定位
- core: 当我们陷入异常循环时中止
- core: 修复 *AutoIgnorer* 相关的死锁
- core: 删除我们的 *.* 前缀，以便更容易发现临时文件
- python: 添加对在没有 ES6 支持的情况下运行的支持
- python: 调整 setup.py 以允许离线安装
- python: 暂时将 prompt-toolkit 版本锁定为 0.38
- frida-repl: 修复 *Memory.readByteArray()* 返回的原始缓冲区的显示
- frida-repl: 修复错误完成时的崩溃
- node: 添加对 DeviceManager 的 *added* 和 *removed* 信号的支持
- node: 添加示例，显示如何监视可用设备
- node: 使用 prebuild 而不是 node-pre-gyp
- node: Babelify *frida.load()* 读取的源代码
- node: 删除 *frida.load()*，因为它现在在 frida-load 模块中

6.0.1:

- python: 停止提供 3.4 二进制文件，改为移动到 3.5
- node: 修复 Linux 链接问题，即我们未能获取 libffi
- node: 也为 Node.js LTS 生成预构建

6.0.2:

- core: 提供 FridaGadget.dylib 用于在没有越狱的情况下检测 iOS 应用程序
- core: 添加对 iOS 模拟器的支持
- core: 改进 *MemoryAccessMonitor* 以允许监视页面上 R、W 或 X 操作的任何组合
- python: 修复 UTF-8 字段在 Python 2.x 上意外暴露为 *str*

6.0.3:

- core: 修复 OS X 上的 *spawn()*

6.0.4:

- core: 添加对独立使用 gadget 的部分支持
- CLI tools: 修复 stdout 编码无法表示所有字符时的崩溃
- frida-trace: 始终将处理程序脚本视为 UTF-8

6.0.5:

- core: 向 NativePointer 添加逻辑右移和左移操作
- core: 改进 Interceptor 以支持附加到已替换的函数
- core: 添加对在 32 位 ARM 上 hook 微小函数的支持
- core: 在 Windows 上模拟 *{Get/Set}LastErrror* 和 TLS 密钥访问，允许我们 hook 更多低级 API

6.0.6:

- core: 修复 iOS 9 上的 launchd / Jetsam 问题
- core: 修复 iOS 9 代码签名问题
- core: 更新命名管道上的安全属性，以允许我们注入更多 Windows 应用程序

6.0.7:

- core: 添加对注入 linux-arm 上进程的支持
- core: 修复 Mac 和 iOS 上与 DebugSymbol API 相关的崩溃
- frida-trace: 改进手册页解析器

6.0.8:

- core: 修复由于未能静态链接 libstdc++ 而导致的 Linux 兼容性问题

6.0.9:

- core: 添加对独立运行 frida-gadget 的支持
- core: 为 Windows 兼容性回归添加临时解决方法
- core: 将 Fruity 后端移植到 Linux，允许直接访问连接的 iOS 设备
- core: 在 JavaScriptCore 运行时中也公开 InvocationContext *context* 读写
- core: 修复 InvocationContext 的 CpuContext 过早被 GC 的问题

6.0.10:

- 重新发布 6.0.9，修复了 Windows 构建回归。

6.0.11:

- core: 防止在网络错误的情况下出现陈旧的 HostSession 对象
- CLI tools: 当 stdout 编码未知时假设 UTF-8
- node: 修复因使用错误的 Nan API 而导致的双重释放

6.0.12:

- core: 更新 Windows 上命名管道的安全属性
- core: 添加 CreateProcessW 标志以防止 Windows 上的 IFEO 循环
- core: 修复 arm 和 arm64 上递归函数的 hook
- python: 修复 Python 3 行尾回归
- node: 更新 prebuild 依赖项

享受吧！
