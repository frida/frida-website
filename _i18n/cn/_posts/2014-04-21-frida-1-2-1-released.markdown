---
layout: news_item
title: 'Frida 1.2.1 发布'
date: 2014-04-21 16:00:00 +0100
author: oleavr
version: 1.2.1
categories: [release]
---

在跟踪 Apple 的加密 API 时获得了一些乐趣，这导致发现了一些错误。所以这里是 1.2.1，带来了一些关键的 ARM 相关错误修复：

-   ARM32: 修复了由于 Apple 的 ABI 与 AAPCS 相比关于 `r9` 的 ABI 差异而在 ARM32 上的 V8 中寄存器破坏问题引起的崩溃。
-   ARM32: 修复 ARM32/Thumb 重定位器分支重写，用于立即同模式分支。
-   ARM64: 改进 ARM64 重定位器以支持重写 `b` 和 `bl`。
