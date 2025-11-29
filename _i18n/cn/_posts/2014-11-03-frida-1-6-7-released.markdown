---
layout: news_item
title: 'Frida 1.6.7 发布'
date: 2014-11-03 16:00:00 +0100
author: oleavr
version: 1.6.7
categories: [release]
---

厌倦了等待 Frida 附加到 64 位 Mac 或 iOS 系统上的 32 位进程？或者也许 `frida-trace` 需要一段时间来解析函数？如果是以上任何一种情况，或者都不是，那么这个版本适合您！

附加到 Mac/iOS 主机上的 32 位进程已得到优化，现在只需几毫秒，而不是几秒钟。但这仅限于 Darwin 操作系统；此版本还加快了所有操作系统上模块导出的枚举速度。现在快了 75%，在使用 `frida-trace` 并等待它解析函数时应该非常明显。

此外，作为额外的奖励，附加到多个进程时的拆卸不再在 Darwin 和 Linux 上崩溃。

享受吧！
