---
layout: news_item
title: 'Frida 16.7.1 发布'
date: 2025-03-21 13:57:25 +0100
author: oleavr
version: 16.7.1
categories: [release]
---

我很高兴宣布 Frida 16.7.1 的发布！在此版本中，我们一直忙于改进对各种架构的支持并修复一些棘手的错误。非常感谢 [@jpstotz][] 和 [@philippmao][] 的宝贵贡献！

**主要亮点包括：**

- **fruity**: 通过跳过具有空 UDID 的设备，修复了 Windows 上的 `Input/Output Error`。（感谢 [@jpstotz][]）

- **droidy**: 通过增加消息大小限制，添加了对超过 ~8 个 ADB 连接设备的支持。（感谢 [@philippmao][]）

- **thumb-relocator**: 通过在 `can_relocate()` 中利用 LLD 对齐填充，提高了在 Android 上 hook 现代工具链生成的微小函数时的成功率。

- **thumb-relocator**: 通过确保最后一条指令在四字节边界上并且是两字节指令，限制了填充检测。

- **module-registry**: 修复了微小 ELF 通知程序的 hook，方法是在 hook 之前填充注册表，允许 `CodeAllocator` 定位附近的 ELF 头。

- **ci**: 将 `arm64be`、`armbe8` 和 `armhf-musl` 添加到 Linux CI。

- **env**: 启用了在 32 位 ARM 上生成 Thumb 代码以获得更小的二进制文件。

- **linux**: 为 32 位 ARM 上的 musl 添加了 pthread 探测。

- **build**: 修复了 musl 的 `armhf` 三元组解析。

- **devkit**: 也为 Gum devkit 定义了 `GUM_STATIC`，因此消费者不必定义它。

- **devkit-assets**: 现代化了 Gum 示例。

- **compiler**: 将 `@types/frida-gum` 升级到 18.8.1。

一如既往，祝黑客愉快！

[@jpstotz]: https://github.com/jpstotz
[@philippmao]: https://github.com/philippmao
