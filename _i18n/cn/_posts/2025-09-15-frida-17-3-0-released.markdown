---
layout: news_item
title: 'Frida 17.3.0 发布'
date: 2025-09-15 22:57:13 +0200
author: oleavr
version: 17.3.0
categories: [release]
---

新鲜的豆子，新功能！此版本为我们的 Barebone 和 Fruity 后端带来了令人兴奋的功能，并消除了一些粗糙的边缘：

- barebone: 添加对 XNU 注入的基本支持，已在 QEMU 中的 iOS 14.0 上成功测试。与 [@hsorbo][] 共同编写。
- barebone: 公开带下划线前缀的 CModule 符号，以便它们可从 Frida 脚本中使用。
- fruity: 每当隧道超时或遇到其他传输错误时，回退到 usbmux。感谢 [@Xplo8E][] 的推动。
- fruity: 处理 CoreDevice 配对事件，并使用 FIFO 而不是序列号匹配配对请求和响应。非常感谢 [@hsorbo][]。
- fruity: 处理拆卸过程中的一些边缘情况。感谢 [@mrmacete][]。

享受吧！


[@hsorbo]: https://x.com/hsorbo
[@Xplo8E]: https://github.com/Xplo8E
[@mrmacete]: https://github.com/mrmacete
