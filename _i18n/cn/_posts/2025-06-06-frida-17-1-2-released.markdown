---
layout: news_item
title: 'Frida 17.1.2 发布'
date: 2025-06-06 22:11:49 +0200
author: oleavr
version: 17.1.2
categories: [release]
---

显然，软件*是*很难的！在发布 17.1.1 仅仅几个小时后，我们又回来发布了一个后续版本，打磨了 **frida-core** 和 **frida-node**。

### frida-core
- **Compiler** – `DeviceManager` 构造函数参数现在是可选的。
  它保留在签名中以保持 ABI 兼容性，但不再使用。

### frida-node (Node.js / N-API bindings)
- **信号处理**
  - 处理程序现在正确接收 `GVariant` 参数。
  - 处理程序内部抛出的异常会传播而不是被吞没。
- **Compiler** – 在连接任何 `output` 信号处理程序时保持运行时存活，防止过早退出。

祝黑客愉快！
