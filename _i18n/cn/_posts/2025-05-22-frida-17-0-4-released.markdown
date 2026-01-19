---
layout: news_item
title: 'Frida 17.0.4 发布'
date: 2025-05-22 21:39:44 +0200
author: oleavr
version: 17.0.4
categories: [release]
---

此版本改进了 Compiler 实现，支撑 frida-tools 的一部分 frida-compile CLI 工具。以下是更改：

- 升级到 **frida-compile 18**，现在使用 TypeScript 5.8.3，最新的 frida-fs 等。
- 修复了 Windows 上的资产打包逻辑，其中虚拟路径使用了错误的路径分隔符进行存储。
