---
layout: news_item
title: 'Frida 4.3 发布'
date: 2015-07-15 19:00:00 +0100
author: oleavr
version: 4.3
categories: [release]
---

现在是发布时间，这次我们在各处都有大量的改进。简而言之：

4.3.0:

- core: 添加对获取有关最前端应用程序详细信息的支持，最初仅适用于 iOS
- python: 添加 *Device.get_frontmost_application()*
- node: 添加 *Device.getFrontmostApplication()*

4.3.1:

- core: 添加对在 arm64 上重定位 PC 相对 *CBZ* 的支持
- frida-repl: 修复 Py3k 上的崩溃和脚本加载

4.3.2:

- core: 添加对使用 URL 启动 iOS 应用程序的支持
- dalvik: 修复字段缓存中的错误
- frida-trace: 根据线程 ID 和深度对事件进行着色和缩进
- frida-ps: 修复 Py3k 上的应用程序列表

4.3.3:

- core: 在意外禁用 Darwin 映射器后重新启用它

4.3.4:

- core: 优雅地处理替换函数的尝试
- core: 当 Interceptor 的 *attach()* 和 *replace()* 失败时抛出异常
- core: 修复 agent 会话的清理
- core: 修复断言日志记录并在 Darwin 上记录到 CFLog
- dalvik: 添加 *Dalvik.synchronized()*、*Dalvik.scheduleOnMainThread()* 和 *Dalvik.isMainThread()*
- dalvik: 将 *Dalvik.androidVersion* 和 *Dalvik.choose()* 移植到 Android 4.2.2
- python: 修复 windows-i386 的 PyPI 下载 URL
- frida-trace: 优雅地处理 *attach()* 失败

4.3.5:

- frida-server: 更好的资源跟踪

4.3.6:

- core: 修复 arm64 函数 hook
- dalvik: 修复 *Dalvik.enumerateLoadedClasses()*

4.3.7:

- objc: 添加 *ObjC.Block* 用于实现和与块交互

享受吧！
