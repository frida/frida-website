---
layout: news_item
title: 'Frida 17.1.1 发布'
date: 2025-06-06 14:11:29 +0200
author: oleavr
version: 17.1.1
categories: [release]
---

喝了一杯新鲜的咖啡后，我敲定了以下改进：

- **构建系统改进**:
  - 将打包切换到 ESBuild 用于：
    - Darwin 上的 `reportcrash.js`。
    - Darwin 上的 `osanalytics.js`。
    - Linux 上的 `system-server.js`。
    - Barebone 后端中的运行时。

- **Barebone 后端修复**:
  - 修复了 ESM 处理，其中未能等待返回的 Promise 导致错误被吞没。现在，任何错误都将被正确报告。
  - 删除了陈旧的 bridge 全局变量。
