---
layout: news_item
title: 'Frida 16.7.4 发布'
date: 2025-03-31 21:23:04 +0200
author: oleavr
version: 16.7.4
categories: [release]
---

此版本包含多项改进和修复，包括对远程服务和通道的支持，以及各种其他增强功能：

- **Core**:
  - 添加了对主机会话中远程服务和通道的支持，允许 `ControlService`/`frida-server` 提供服务会话和通道。
  - 修复了 `ControlService` 中远程设备的会话逻辑。

- **Compiler**:
  - 将 `frida-compile` 和 `@types/frida-gum` 升级到最新版本。

- **Python Bindings**:
  - 修复了 `IOStream.read_all()` 流结束处理。

一如既往，祝黑客愉快！
