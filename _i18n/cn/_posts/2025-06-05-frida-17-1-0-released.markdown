---
layout: news_item
title: 'Frida 17.1.0 发布'
date: 2025-06-05 22:05:33 +0200
author: oleavr
version: 17.1.0
categories: [release]
---

包含几个令人兴奋的改进的大版本发布！

首先，我们在 Compiler 后端切换到了 ESBuild 和 typescript-go，从而大幅提高了性能，并通过不再需要维护打包器来减轻了我们的维护负担。我们还添加了配置输出和包格式的选项，并支持禁用类型检查。

其次，我们现在终于发布了 Windows/ARM64 的二进制文件。这是由 GitHub 向公众提供 Windows ARM64 托管运行器解锁的。

特别感谢 [@mrmacete][] 堵住了 Interceptor 单例泄漏，以及 [@fesily][] 实现了 Windows 上的 `Module#enumerateSections()`，以及改进了 `Module#enumerateImports()` 以公开 `slot`。

以下是完整的更改列表：

- **Compiler 改进**:
  - 在 Compiler 后端切换到 ESBuild 和 typescript-go。
  - 添加了配置输出和包格式的选项，并支持禁用类型检查。
- **Windows/ARM64 支持**:
  - CI 更新为发布 Windows/arm64 二进制文件。
- **来自我们社区的贡献**:
  - 修复了针对 Thumb 地址的 32 位 ARM 断点逻辑。
  - 堵住了 Interceptor 单例泄漏 ([@mrmacete][])。
  - 实现了 `Module#enumerateSections()` 并在 Windows 上连接了导入槽 ([@fesily][])。

[@mrmacete]: https://twitter.com/bezjaje
[@fesily]: https://github.com/fesily
