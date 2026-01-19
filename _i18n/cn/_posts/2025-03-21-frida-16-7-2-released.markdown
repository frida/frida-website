---
layout: news_item
title: 'Frida 16.7.2 发布'
date: 2025-03-21 14:21:02 +0100
author: oleavr
version: 16.7.2
categories: [release]
---

同一天发布的另一个快速错误修复版本——事实证明软件很难！

我卷起袖子修复了以下问题：

- droidy: 修复 `MAX_MESSAGE_LENGTH` 声明。新的最大值超出了 `uint16` 的范围。
