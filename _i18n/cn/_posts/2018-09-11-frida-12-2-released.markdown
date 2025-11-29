---
layout: news_item
title: 'Frida 12.2 发布'
date: 2018-09-11 21:00:00 +0200
author: mrmacete
version: 12.2
categories: [release]
---

让我们谈谈 iOS 内核内省。Frida 获得对 iOS 内核内省的基本支持已经有一段时间了，但在过去几个月中，我们一直在改进它。今天的版本包括对我们的 Kernel API 的重大补充，以支持最新的 64 位内核。

## 内核基址

您可以通过读取 `Kernel.base` 属性来获取内核的基地址。拥有基址可以例如计算您从内核缓存的静态分析中已经知道的任何符号的滑动虚拟地址。

## 内核内存搜索

内存搜索 API 已移植到 Kernel，因此您可以像在用户空间中使用 `Memory.scan()`（或 `Memory.scanSync()`）一样使用 `Kernel.scan()`（或 `Kernel.scanSync()`）。这是一个强大的原语，结合最近的位掩码功能，允许您通过搜索 arm64 模式来创建自己的符号查找代码。

## KEXT 和内存范围

使用 `Kernel.enumerateModules()`（或 `Kernel.enumerateModulesSync()`）现在可以获取所有 KEXT 的名称和偏移量。

`Kernel.enumerateModuleRanges()`（或 `Kernel.enumerateModuleRangesSync()`）是枚举属于模块（按名称）的 Mach-O 节定义的所有内存范围的方法，按保护进行过滤。结果类似于在用户空间中调用 `Module.enumerateRanges()` 时可以获得的结果，但它还包括节名称。

## 最后说明

所有 Kernel API 都不依赖于 `NativePointer`，因为其大小取决于用户空间，而用户空间不一定与内核空间匹配。相反，所有地址都表示为 `UInt64` 对象。

所有这些，加上现有的用于读取、写入和分配内核内存的 JavaScript 接口，可以为构建您自己的内核分析或漏洞研究工具提供强大的起点。

请注意，这被认为是实验性的，以随机方式搞乱内核可能会严重损坏您的设备，所以要小心，祝您 hacking 愉快！

## 故障排除

### 问题：Kernel.available 为 false

如果满足以下两个条件，则 Kernel API 可用：

- 您的设备已越狱
- Frida 能够获得对内核任务的发送权限，无论是通过传统的 `task_for_pid (0)` 还是通过访问主机特殊端口 4（这是现代越狱正在做的）

完成后者的推荐方法是附加到系统会话，即 PID 0，并在那里加载您的脚本。

### 问题：无法对我的 32 位内核做太多事情

是的，这在将来可能会改进，但 32 位 iOS 现在在优先级列表中相当靠后，但非常欢迎您贡献并发送 PR。

### 问题：我试图做 X，内核崩溃了

别担心，这很正常。您可以转到设备上的 `/private/var/mobile/Library/Logs/CrashReporter` 目录，或导航到设置 -> 隐私 -> 分析 -> 分析数据，找到您的崩溃日志并弄清楚您（或 Frida）做错了什么。记住：内核总是对的！

### 问题：我使用 Frida Kernel API 不可恢复地损坏了我的设备

很遗憾听到这个消息，如果损坏是在硬件级别，并且您可以投入足够的时间和金钱，您可能可以通过遵循 [https://ifixit.com](https://ifixit.com) 上的教程自己修复它。
