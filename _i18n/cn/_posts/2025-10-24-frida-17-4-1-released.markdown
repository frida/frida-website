---
layout: news_item
title: 'Frida 17.4.1 发布'
date: 2025-10-24 15:25:28 +0200
author: oleavr
version: 17.4.1
categories: [release]
---

一个小而美味的后续版本，以保持势头：

- android: 升级 `system-server` 中的 `frida-java-bridge`，带来最新的稳定性改进：
  - android: 处理静态 trampoline 修复，因此我们将每个 ArtMethod 回滚到其先前的入口点，以避免 hook 被绕过。
  - android: 在 GC 后同步 ArtMethod 类字段，以便我们的替换 ArtMethod 实例不会过时，并导致未定义的行为。
  感谢结对编程，[@hsorbo][]。
- devkit-assets: 将 GumJS 示例升级到新的 Frida 17 GumJS API。感谢 [@Hexploitable][] 促成此事。
- freebsd: 连接 PTY 支持，因此依赖于控制终端的 spawn/attach 操作现在开箱即用。

享受吧！


[@hsorbo]: https://x.com/hsorbo
[@Hexploitable]: https://x.com/Hexploitable
