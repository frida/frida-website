---
layout: news_item
title: 'Frida 16.0.6 发布'
date: 2022-12-01 01:23:12 +0100
author: oleavr
version: 16.0.6
categories: [release]
---

事实证明，Frida 16.0.3 中出现了一个严重的稳定性回归，我们用于 Apple OS 的进程外动态链接器最终可能会导致目标进程崩溃。当目标进程是 launchd 时，这尤其具有灾难性，因为它会导致内核恐慌。感谢 [@mrmacete][] 的出色工作，这个令人尴尬的回归现已修复。🎉 享受吧！


[@mrmacete]: https://twitter.com/bezjaje
