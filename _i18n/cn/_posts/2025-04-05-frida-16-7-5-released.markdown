---
layout: news_item
title: 'Frida 16.7.5 发布'
date: 2025-04-05 08:52:28 +0200
author: oleavr
version: 16.7.5
categories: [release]
---

我们很高兴宣布 Frida 16.7.5，它改进了我们的构建系统和 API，并修复了 Darwin 平台的关键问题。以下是新内容：

- **Darwin**: 修复 `find_module_by_address` 中的双重释放。（感谢 [@mrmacete][]。）

- **Darwin**: 更新线程列表指针雕刻以支持最近的 iOS 版本。在这些版本中，`pthread_from_mach_thread_np()` 中的线程列表指针通过 `ADRP + LDR` 而不是 `ADRP + ADD` 引用。（感谢 [@mrmacete][] 的贡献。）

- **API**: 修复密封类的 VAPI 条目。

- **API**: 删除一些意外公开的类型。

- **API**: 密封不打算被子类化的类，防止意外的子类化。

- **构建系统**: 为方便起见提供 `Gio-2.0.gir`，因此用户在构建语言绑定并将 Frida 作为子项目使用时不需要安装任何 GObject Introspection 包。

- **构建系统**: 修复未安装情况下的 `frida_girdir`。它现在正确指向包含精炼 `.gir` 文件的目录，而不是来自 Vala 编译器的原始文件。


[@mrmacete]: https://twitter.com/bezjaje
