---
layout: news_item
title: 'Frida 16.4.9 发布'
date: 2024-08-20 21:50:56 +0200
author: oleavr
version: 16.4.9
categories: [release]
---

快速的错误修复版本，旨在解决一些问题：

- tunnel-interface-observer: 修复 i/tvOS 上 SCDynamicStoreCopyKeyList() 失败时的 start() 崩溃。感谢 [@mrmacete][]！
- darwin-mapper: 在构造函数之前初始化 TLV。感谢 [@jiska][]！
- darwin-mapper: 修复 arm64 的 TLV 初始化运行时代码。感谢 [@jiska][]！
- arm64-writer: 修复 UBFM 和 LS{L,R} 的编码。感谢 [@jiska][]！


[@mrmacete]: https://twitter.com/bezjaje
[@jiska]: https://chaos.social/@jiska
