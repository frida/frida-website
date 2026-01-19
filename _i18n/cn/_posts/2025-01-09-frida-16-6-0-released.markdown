---
layout: news_item
title: 'Frida 16.6.0 发布'
date: 2025-01-09 13:18:51 +0100
author: oleavr
version: 16.6.0
categories: [release]
---

很高兴宣布 Frida 16.6.0，其特点是对模块符号处理的重大改进、性能增强和错误修复。

以下是亮点：

- **android**: 提高 ART 兼容性：
  - 既然 Frida 支持解析 `.gnu_debugdata`，那么当导出丢失时查找符号。
  - 处理 runFlip 签名的更改 (感谢 [@matbrik][])。
- **android**: 修复 enumerateLoadedClasses() 中的溢出 (感谢 [@123edi10][])。增量创建和清理全局引用，而不是在开始和结束时一次性处理所有引用。
- **android**: 在 registerClass() 中支持静态方法 (感谢 [@5andr0][])。
- **java**: 修复 32 位系统上由 JVMTI 驱动的 Java.choose()。
- **module**: 将 Module API 转换为实例方法，以便可以有效地执行多个查询。以前这仅在 JavaScript (GumJS) 级别建模，其中此类 JS 对象将模块的路径作为字符串，传递给每个查询，例如 `enumerateExports()`。底层 C API 现在也以相同的方式建模。
- **gumjs**: 添加 `findSymbolByName()` 和 `getSymbolByName()` 方法。提供按名称直接、本机查找符号，而不是枚举所有符号并在 JavaScript 中过滤它们。
- **module**: 优化 `find_symbol_by_name()` 回退。当 Module 实现缺乏优化的符号查找方法时，构建排序索引并对其进行二进制搜索。
- **elf-module**: 如果未找到符号，则使用 MiniDebugInfo。当 `enumerate_symbols()` 遇到内存中没有符号的 ELF 时，实例化离线 `ElfModule` 实例并解析 `.gnu_debugdata` 部分。解压缩嵌入的 ELF 并重用其符号作为回退。
- **ncm**: 通过将每次传输的数据报限制上限为 16 来提高我们的用户空间 USB CDC-NCM 驱动程序的性能 (感谢结对编程，[@hsorbo][]!)。
- 移植到新的 `Gum.Module` API。过渡到实例方法以允许有效地执行多个查询。
- 放弃对在没有 GObject 的情况下运行的支持。占用的节省微乎其微，并且不能证明增加的复杂性和降低的代码可读性是合理的。
- **gumjs**: 修复 V8 `NativeCallback` use-after-free (非 Interceptor)，其中 `CpuContext` 的作用域太窄。

一如既往，祝黑客愉快！

[@matbrik]: https://github.com/matbrik
[@123edi10]: https://github.com/123edi10
[@5andr0]: https://github.com/5andr0
[@hsorbo]: https://twitter.com/hsorbo
