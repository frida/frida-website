---
layout: news_item
title: 'Frida 17.0.5 发布'
date: 2025-05-24 21:03:32 +0200
author: oleavr
version: 17.0.5
categories: [release]
---

快速的错误修复版本，用于修复由最新 frida-compile 生成的代理。既然 TypeScript 编译器更加一致并最终生成 CommonJS 胶水代码，我们现在需要显式地将内部代理声明为 ESM。这修复了我们的 Darwin 和 Android 代理，以及 Barebone 后端的脚本运行时。
