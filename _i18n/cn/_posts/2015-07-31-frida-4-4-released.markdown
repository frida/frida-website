---
layout: news_item
title: 'Frida 4.4 发布'
date: 2015-07-31 19:00:00 +0100
author: oleavr
version: 4.4
categories: [release]
---

随着 4.4 的发布，我们现在可以为您提供全新的 [RPC API](/docs/javascript-api/#rpc)，使与脚本通信并让它们向您的应用程序公开服务变得超级容易。我们还从 [Adam Brady](https://github.com/SomeoneWeird) 那里获得了一些惊人的贡献，他刚刚将 frida-node 移植到 [Nan](https://github.com/nodejs/nan)，使其易于为多个版本的 Node.js 构建。

总结一下这个版本：

- core: 添加新的 RPC API
- python: 添加对调用 RPC 导出的支持
- node: 添加对调用 RPC 导出的支持
- node: 允许发布的消息值是任何可序列化为 JSON 的东西
- node: 移植到 Nan

享受吧！
