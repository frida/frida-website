---
layout: news_item
title: 'Frida 16.7.3 发布'
date: 2025-03-21 15:43:12 +0100
author: oleavr
version: 16.7.3
categories: [release]
---

好吧，有时软件很难。这是一个修复我们 CI 的快速更新：

- ci: 暂时从 package-linux 作业中删除 arm64beilp32。由于某些组件尚未移植到此架构，我们将暂停将其包含在我们的 Linux 包中，直到移植工作完成。

- ci: 将 pypa/gh-action-pypi-publish 升级到最新的 v1。
