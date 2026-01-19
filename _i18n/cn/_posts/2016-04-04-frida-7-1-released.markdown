---
layout: news_item
title: 'Frida 7.1 发布'
date: 2016-04-04 02:00:00 +0100
author: oleavr
version: 7.1
categories: [release]
---

如果您曾经使用 Frida 启动使用 stdio 的程序，您可能会对生成的进程的 stdio 状态如何相当未定义并且让您几乎无法控制感到沮丧。从这个版本开始，我们已经开始解决这个问题，程序现在总是通过重定向 *stdin*、*stdout* 和 *stderr* 来启动，您甚至可以将自己的数据输入到 *stdin* 并获取写入 *stdout* 和 *stderr* 的数据。Frida 的 CLI 工具免费获得此功能，因为这在 *ConsoleApplication* 基类中已 [wired up](https://github.com/frida/frida-python/blob/4afd9debd489e3920b85cb6c542de10aabb0dcce/src/frida/application.py#L212)。如果您不使用 *ConsoleApplication* 或者您使用不同的语言绑定，只需连接到 *Device* 对象的 *output* 信号，每次发出此信号时，您的处理程序都会获得三个参数：*pid*、*fd* 和 *data*，按此顺序。点击同一类上的 *input()* 方法以写入 *stdin*。这就是全部内容。

既然我们已经跨平台规范化了 stdio 行为，我们稍后将能够添加 API 来禁用 stdio 重定向。

除此之外和许多错误修复，我们还极大地改进了在 Darwin（Mac 和 iOS）上启动普通程序的支持，其中 *spawn()* 现在在两者上都快如闪电，并且不再弄乱 iOS 上的代码签名状态。

对于那些对 Mac 和 iOS 应用程序进行高级检测的人来说，现在还有全新的 API 用于在运行时动态创建自己的 Objective-C 协议。我们已经支持创建新类和代理对象，有了这个新 API，您可以做得更多。

最后，这是更改的摘要：

7.1.0:

- core: 添加 *Device.input()* API 用于写入生成进程的 *stdin*
- core: 添加 *Device.output* 信号用于传播来自生成进程的输出
- core: 在 Windows、Darwin 和 Linux 后端实现新的 *spawn()* stdio 行为
- core: 由于 4.x 中的非平凡回归，暂时降级到 Capstone 3.x
- node: 添加对新 stdio API 的支持
- node: 添加错误路径缺少的返回
- python: 添加对新 stdio API 的支持

7.1.1:

- core: 修复 *spawn()* 中的间歇性崩溃

7.1.2:

- core: 重做 Darwin 上的 *spawn()* 实现，现在更快更可靠
- core: 添加对在 Darwin 上枚举和查找动态符号的支持
- core: 修复 Darwin Mach-O 解析器中的页面大小计算

7.1.3:

- core: 恢复临时 hack

7.1.4:

- python: 修复 EOF 时的 *ConsoleApplication* 崩溃
- frida-trace: 退出前刷新排队的事件

7.1.5:

- frida-repl: 改进 REPL 自动完成
- objc: 添加 *ObjC.registerProtocol()* 用于动态协议创建
- objc: 修复类名冲突的处理
- objc: 允许代理被命名

7.1.6:

- python: 修复 setup.py 下载回退

7.1.7:

- python: 改进 setup.py 下载回退

7.1.8:

- python: 修复 setup.py 本地回退并在主目录中查找

7.1.9:

- core: 修复附加到同一 pid 的重叠请求的处理
- core: (Darwin) 修复没有 *attach()* 的 *spawn()*
- core: (Darwin) 修复关闭请求重叠时的崩溃
- frida-server: 始终回收相同的临时目录

7.1.10:

- core: (Windows) 从 VS2013 升级到 VS2015
- node: 添加 Node.js 6.x 的预构建
- python: 修复 Python 2.x 上 unicode 命令行参数的处理
- qml: 在 Mac 上使用 libc++ 而不是 libstdc++

7.1.11:

- core: 当远程 Frida 不兼容时提供适当的错误消息
- core: 忽略从系统会话分离的尝试
- core: 防止 *create_script()* 和 *detach()* 重叠
- core: 修复 *setTimeout()* 使延迟是可选的，默认为 0
- core: (V8 runtime) 修复关闭的 *File* 对象被 GC 时的崩溃
- core: (Darwin) 修复拆卸时的间歇性崩溃
- core: (QNX) 修复 *gum_module_find_export_by_name()* 的实现
- core: (QNX) 实现临时 TLS 存储
- frida-repl: 监视加载的脚本并在更改时自动重新加载
- node: 处理日志消息时考虑 *level*，以便 *console.warn()* 和 *console.error()* 转到 *stderr* 而不是 *stdout*
- node: 不让会话保持运行时活动

7.1.12:

- core: 修复 *Memory.readByteArray()* 对于 size = 0 的返回值

7.1.13:

- core: (Linux/Android) 修复具有首选基址的库的导出地址计算
- core: 修复 Android 6.0 上的 *Java API not available* 错误
- java: 通过考虑操作系统版本和架构来改进 ART 支持
- frida-repl: 添加 *--no-pause* 以不在启动时暂停生成的进程

享受吧！
