---
layout: news_item
title: 'Frida 17.1.4 发布'
date: 2025-06-10 22:10:02 +0200
author: oleavr
version: 17.1.4
categories: [release]
---

很高兴宣布 Frida 17.1.4，它带来了几个重要的修复和改进 —— 最值得注意的是 Android 16 支持。以下是新内容：

- **Compiler**: 将 esbuild 的 `platform` 切换为 `node`，以便 `package.json` 的 `main` 和 `exports` 以 Node.js 方式解析，恢复了依赖它的包的兼容性。感谢 [@hsorbo][] 帮助追踪此问题。
- **Plist**: 修复了二进制属性列表的 `offsetIntSize`，确保与 Core Foundation 的兼容性。感谢 [@mrmacete][] 帮助追踪此问题。
- **Plist**: XML 输出中的空字典和数组现在使用自闭合标签 (例如 `<dict/>`)，以匹配 Apple 的编码器。
- **Android**: 将 `system_server` 代理中的 `frida-java-bridge` 升级到 7.0.3，添加了 Android 16 支持。感谢 [@tbodt][] — 并感谢 [@thinhbuzz][] 贡献了一个错误处理补丁，解决了某些 Android 12 设备上的不可操作性问题。
- **Darwin**: 将内部代理中的 `frida-objc-bridge` 升级到 8.0.5。
- **GumJS**: 修复了 FFI 参数的大端处理。

我们建议所有用户尽早升级。确保你也升级到刚刚发布的 frida-tools 14.1.2。

[@hsorbo]: https://twitter.com/hsorbo
[@mrmacete]: https://twitter.com/bezjaje
[@tbodt]: https://mastodon.social/@tbodt
[@thinhbuzz]: https://github.com/thinhbuzz
