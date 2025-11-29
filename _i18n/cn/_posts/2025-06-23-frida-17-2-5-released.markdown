---
layout: news_item
title: 'Frida 17.2.5 发布'
date: 2025-06-23 18:44:36 +0200
author: oleavr
version: 17.2.5
categories: [release]
---

此版本为 Frida 带来了重要的修复和改进。以下是亮点：

- frida-node: 保持 TSFN 存活直到 promise 解决，防止可能导致 Node.js 提前退出并显示“检测到未解决的顶级 await”警告的竞争条件。感谢 [@mrmacete][] 和 [@hsorbo][] 帮助追踪此问题。

- frida-node: 简化 `findMatchingDevice()` (与 [@hsorbo][] 共同编写)。

- package-manager: 仅在明确请求时才升级。

- package-manager: 修复 `dev` 逻辑。

- docs: 修复 README 中的 Mapper URL (感谢 [@cmdlinescan][])。


[@mrmacete]: https://twitter.com/bezjaje
[@hsorbo]: https://twitter.com/hsorbo
[@cmdlinescan]: https://github.com/cmdlinescan
