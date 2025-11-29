---
layout: news_item
title: 'Frida 4.5 发布'
date: 2015-09-10 19:00:00 +0100
author: oleavr
version: 4.5
categories: [release]
---

是时候发布另一个打包版本了。这次我们带来了全新的 spawn gating API，让您可以捕获系统生成的进程，以及大量的 Android 改进和各处的改进。

因此，事不宜迟，更改列表如下：

4.5.0:

- core: 添加 *Process.pageSize* 常量
- core: 当 size >= page size 时，让 *Memory.alloc()* 分配原始页面
- core: 修复 NativeFunction 对小返回类型的处理
- core: 重写 BLX 指令时修复 PC 对齐
- core: 添加 spawn gating API
- core: 在 Android 上实现 *get_frontmost_application()*
- core: 在 Android 上实现 *enumerate_applications()*
- core: 添加对启动 Android 应用程序的支持
- core: 添加对注入 Android 上 arm64 进程的支持
- core: 添加对 Android M 的支持
- core: 修补内核的实时 SELinux 策略
- core: 与 SuperSU 集成以解决 Samsung 内核上的限制
- core: 解决 Android 上损坏的 sigsetjmp，以及许多其他 Android 修复
- core: 修复 Linux 上枚举模块时的崩溃
- core: 优化 Darwin 上远程进程的导出枚举
- dalvik: 移植到 ART 并弃用 *Dalvik* 名称，现在称为 *Java*
- java: 添加 *Java.openClassFile()* 以允许在运行时加载类
- java: 修复数组转换和字段设置器
- python: 添加对新 spawn gating API 的支持
- python: 允许脚本源和名称在 Python 2.x 上也是 unicode
- python: 修复 Python 3.x 中的错误传播
- python: 修复 Linux 下载 URL 计算
- node: 添加对新 spawn gating API 的支持
- node: 移植到 Nan 2.x

4.5.1:

- core: 修复 `ensure_host_session()` 错误传播

享受吧！
