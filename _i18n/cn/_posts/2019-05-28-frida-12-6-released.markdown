---
layout: news_item
title: 'Frida 12.6 发布'
date: 2019-05-28 02:00:00 +0200
author: oleavr
version: 12.6
categories: [release]
---

在过去几周内跨所有平台进行了一系列修复之后，我认为是时候再做一次小版本升级来引起对此版本的关注了。

有一个特定的修复值得特别提及。我们的 Android Java 集成中存在一个长期存在的错误，其中异常传递会间歇性地导致进程崩溃，堆栈跟踪中通常有 *GetOatQuickMethodHeader()*。向 [Jake Van Dyke][] 和 [Giovanni Rocca][] 致敬，感谢他们帮助追踪这个问题。自从支持 ART 以来，这个错误就一直存在，所以这个修复值得庆祝。🎉

我们的 V8 运行时也更加稳定，子进程门控比以往任何时候都更好，Android 设备兼容性大大提高等。

所以底线是这是有史以来发布的最稳定的 Frida 版本 —— 现在是确保您运行 Frida 12.6 的时候了。

享受吧！

### 12.6.1 中的变化

- Android Java 集成中的异常传递修复在以解释器模式运行 VM 时引入了性能瓶颈，例如通过 *Java.deoptimizeEverything()*。例如，在运行 Android 9 的 Pixel 3 上从启动到登录屏幕运行 Dropbox 应用程序时，这将需要约 94 秒，现在需要约 6 秒。

### 12.6.2 中的变化

- 感谢 [Giovanni Rocca][] 贡献的修复，Android Java 集成现在支持更多 arm64 系统。
- Android Java 集成再次支持同时被多个脚本使用。

### 12.6.3 中的变化

- 感谢 [Eugene Kolo][] 贡献的修复，*Java.choose()* 现在在 Android >= 8.1 上再次工作。
- Android Java 集成 unhooking 现在再次工作。这也意味着 hook 在脚本卸载时被正确恢复。
- Frida 现在可以与旧版本的 Frida 对话，从添加每脚本运行时选择之前的版本开始。

### 12.6.4 中的变化

- 构建系统在所有平台上恢复正常。

### 12.6.5 中的变化

- Linux 线程枚举现在在 x86-64 上正常工作。
- Stalker 终于处理可重启的 Linux 系统调用。

### 12.6.6 中的变化

- Android Java 集成在 32 位 ARM 上恢复完全工作状态。

### 12.6.7 中的变化

- 现在支持最新的 Chimera iOS 越狱；确认在 *1.0.8* 上工作。
- Linux 注入器处理 libc 名称不明确的目标进程，这在 Android 上经常是一个问题。

### 12.6.8 中的变化

- *ObjC.Object* 现在提供 *$moduleName*，用于确定哪个模块拥有给定的类。感谢 [David Weinstein][] 贡献这个巧妙的功能！

### 12.6.9 中的变化

- 现在完全支持最新的 unc0ver 越狱。
- 早期插桩逻辑已得到改进，以完全支持 iOS 12。感谢 [Francesco Tamagni][] 帮助完成这些棘手的更改。
- iOS 12 上的内存范围枚举现在更可靠，因为属于线程的内存范围现在被正确隐藏。
- 隐藏的内存范围现在被压缩，使查找更快。
- 子进程门控能够保持子进程超过 25 秒。以前这些会在那个意外超时后自动恢复。这也影响 Android 上的早期插桩，因为它建立在子进程门控之上。
- 感谢 [John Coates][] 的出色贡献，Swift 绑定支持 RPC 并已移至 Swift 5.0。

### 12.6.10 中的变化

- 内存范围枚举现在在所有平台上都是可靠的。当删除最终拆分现有范围时，存在一个长期存在的错误。

### 12.6.11 中的变化

- 感谢 [CodeColorist][] 的出色修复，iOS >= 12 上的应用程序枚举包括图标。
- 感谢 [gebing][] 的巧妙贡献，Gadget 学会了如何检测 Android 应用程序的可执行文件和包名称。
- 内存范围隐藏得到了影响 Windows 用户的关键修复。

### 12.6.12 中的变化

- *frida-inject* 工具现在支持通过 *-P/--parameters* 将参数传递给脚本。感谢 [Eugene Kolo][] 贡献这个巧妙的功能。
- 当脚本卸载阻塞时，子进程门控不再死锁。感谢 [Ioannis Gasparis][] 帮助追踪这个问题。
- 子进程门控更可靠，因为 Frida 现在在更高的范围内分配文件描述符，以避免它们在 *fork()+exec()* 期间被调用 *dup2()* 的应用程序关闭。这通常会在 Android 上的应用程序调用 *Runtime.exec()* 时发生。感谢 [Ioannis Gasparis][] 帮助追踪这个问题。
- 感谢 [Muhammed Ziad][] 的一系列出色贡献，痛苦的 Android NDK 升级到 r20 已完成。
- 错误处理得到改进，以避免在由于缺乏权限而无法初始化的场景中崩溃。感谢 [pancake][] 报告。
- 长期以来一直在分支中的 iOS 本机 lockdown 集成终于合并了。它未完成并被认为是不稳定的 API，但由于正在进行的重大重构而不得不合并。
- *Stalker* 现在允许从 *transform* 回调中调用 *unfollow()*，而不是像以前那样使进程崩溃。感谢 [Giovanni Rocca][] 帮助修复这个问题。
- Gadget 的 Android 包名称检测逻辑得到改进，以处理以前未考虑的一个边缘情况。感谢 [xiaobaiyey][] 报告并建议修复。
- *Java.registerClass()* API 得到改进，以支持指定超类，以及对该 API 和处理带泛型的数组的一系列修复。非常感谢 [gebing][] 提供的这些出色改进。

### 12.6.13 中的变化

- Agent 和 Gadget 中的构造函数/析构函数现在终于正确排序，我们的 libc shim 的内存分配器 hack 可以被删除。这些脆弱的 hack 由于工具链的 *libgcc* 中的微妙变化而在 Android 上的 32 位 ARM 进程中以新的和丰富多彩的方式破坏。
- 我们的 libc shim 现在还处理 *__cxa_atexit()* 和 *atexit()*，其中前者对于避免泄漏至关重要。

### 12.6.14 中的变化

- 感谢 [gebing][] 贡献的出色改进，*Java.registerClass()* API 得到改进，以支持用户定义的构造函数和字段。
- 临时文件现在在所有平台上都被清理。
- frida-server 在 Windows 上处理 Ctrl+C 以支持优雅关闭而不留下临时文件。

### 12.6.15 中的变化

- *NativePointerValue*，即除了 *NativePointer* 之外还支持传递具有 *handle* 属性的对象，现在在所有地方再次工作。

### 12.6.16 中的变化

- *frida-gadget-ios* 元包现在是无依赖的。

### 12.6.17 中的变化

- 崩溃报告器集成现在与 iOS 12.4 兼容。
- Java 集成得到改进，在调用替换方法时急切地释放全局句柄，以避免耗尽句柄。感谢 [gebing][] 提供的这个不错的改进。
- 添加了 *Java.retain()* 以允许在替换的 Java 方法之外存储 *this* 以供以后使用。
- 对旧版本 Android 的支持现在应该稍微好一点。
- 如果目标进程在向其注入库时死亡，Frida 不再在 i/macOS 上崩溃。
- 感谢 [Jon Wilson][] 的出色贡献，支持 MIPS64。
- 感谢 [gebing][] 的修复，*Memory.patchCode()* 不再在 *android-arm64* 上崩溃。
- 拦截已拦截的 Thumb 函数现在正常工作。
- Frida 在 iOS 上的进程生命周期早期记录日志时不再崩溃。
- 简单的 *ModuleApiResolver* 查询现在速度极快。
- *Duktape* 运行时不再包括有问题的 *Reflect* 内置。
- *Interceptor* C API 被重构以改进命名。

### 12.6.18 中的变化

- Gadget 二进制文件在所有平台上再次被剥离。

### 12.6.19 中的变化

- 所有 API 现在都是可取消的。Python 和 Node.js 语言绑定支持传递 *Cancellable* 对象。其余语言绑定像以前一样工作，非常欢迎贡献。

### 12.6.20 中的变化

- *DeviceManager.find_device()* 在启动时不再崩溃。

### 12.6.21 中的变化

- *Future.wait_async()* 在最后一刻取消时不再崩溃。

### 12.6.22 中的变化

- 状态管理得到改进，以允许在已处置状态下也使用 *eternalize()* 和 *post()*。
- *dispose()* RPC 导出现在传递一个指定原因的参数，以便能够区分 *unload*、*exit* 和 *exec*。
- 如果 exec 转换失败，脚本现在可以再次 *dispose()*。
- *frida-inject* CLI 工具得到改进，以在分离时退出。
- *RpcClient* 在 *post_rpc_message()* 失败时不再崩溃。
- *Fruity* 和 *Droidy* 后端现在在 iOS 和 Android 上被禁用，以减少这些后端不适用的平台上的占用空间大小。

### 12.6.23 中的变化

- 当 *HostSession* 在请求中途丢失时，Frida 不再崩溃。


[Jake Van Dyke]: https://twitter.com/giantpune
[Giovanni Rocca]: https://twitter.com/iGio90
[Eugene Kolo]: https://twitter.com/eugenekolo
[David Weinstein]: https://twitter.com/insitusec
[Francesco Tamagni]: https://twitter.com/bezjaje
[John Coates]: https://twitter.com/JohnCoatesDev
[CodeColorist]: https://twitter.com/CodeColorist
[gebing]: https://github.com/gebing
[Ioannis Gasparis]: https://github.com/igasparis
[Muhammed Ziad]: https://github.com/muhzii
[pancake]: https://twitter.com/trufae
[xiaobaiyey]: https://github.com/xiaobaiyey
[Jon Wilson]: https://github.com/jonwilson030981
