---
layout: news_item
title: 'Frida 16.1.6 发布'
date: 2023-11-13 22:43:57 +0100
author: oleavr
version: 16.1.6
categories: [release]
---

只是一个快速的错误修复版本，用于回滚上一版本中进入的两个 Interceptor/Relocator arm64 更改。事实证明，这些需要在落地之前进行更多改进，因此我们暂时将其回滚。

### 变更日志

- Revert "relocator: Improve scratch register strategy on arm64".
- Revert "interceptor: Relocate tiny targets on arm64".
- stalker: 允许 transformer 在 arm64 上跳过调用。
