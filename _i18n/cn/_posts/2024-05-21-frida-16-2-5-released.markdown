---
layout: news_item
title: 'Frida 16.2.5 发布'
date: 2024-05-21 12:50:43 +0200
author: oleavr
version: 16.2.5
categories: [release]
---

一个快速的错误修复版本，包含三个改进：

- ci: 修复 macOS 的 frida-node 预构建循环，以便我们为所有目标生成预构建，而不仅仅是第一个。
- node: 避免依赖 package-lock.json，以支持在缺少预构建时的回退构建。
- android: 在 Java.registerClass() 中将 DexFile 设置为只读。从 Android 14 开始，targetSdk >= 34 的应用程序不允许对动态加载的 Dex 文件具有可写权限。感谢 [@pandasauce][]！

享受吧！


[@pandasauce]: https://github.com/pandasauce
