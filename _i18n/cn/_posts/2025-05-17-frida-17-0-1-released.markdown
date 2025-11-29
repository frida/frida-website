---
layout: news_item
title: 'Frida 17.0.1 发布'
date: 2025-05-17 23:48:23 +0200
author: oleavr
version: 17.0.1
categories: [release]
---

惊喜！我们在 17.0.0 发布的同一天发布了一个快速补丁版本。事实证明软件很难！

此版本包含以下修复：

- **Core**: 更新接口版本以匹配主版本。
- **Darwin**: 将 `frida-objc-bridge` 升级到版本 8.0.4。
- **Android**: 将 `frida-java-bridge` 升级到版本 7.0.1。
- **frida-node**: 修复 `Device.openChannel()` 的返回类型，以避免公开我们将来可能想要更改的实现细节。
