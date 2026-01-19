---
layout: news_item
title: 'Frida 17.2.7 发布'
date: 2025-07-01 23:40:14 +0200
author: oleavr
version: 17.2.7
categories: [release]
---

我们很高兴宣布 Frida 17.2.7 的发布，其特点是对我们的包管理器进行了重大改进。

- **package-manager**: 改进解析和提升以更紧密地模仿 npm 的行为。与 [@hsorbo][] 共同编写。感谢您的帮助！
- **package-manager**: 为 `role` 添加 `install()` 选项，实现相当于 npm install 的 `--save-*` 开关。
- **package-manager**: 为 `omits` 添加 `install()` 选项，以实现相当于 npm install 的 `--omit=x` 开关。
- **package-manager**: 改进对可选包的处理。
- **package-manager**: 在非 Windows 系统上提取时处理文件模式。
- **package-manager**: 修复 `has_install_script` 逻辑以同时考虑 `preinstall` 和 `postinstall` 脚本。
- **meson**: 澄清 Vala 构建系统说明。Vala README 仅提到 autotools 说明，当以这种方式编译 Vala 时，`-frida` 后缀不会添加到版本字符串中，导致 frida-core 对 Vala 的检查失败。我们现在澄清 Vala 需要使用 Meson 从源代码构建。感谢 [@grimler][] 指出这一点！


[@hsorbo]: https://twitter.com/hsorbo
[@grimler]: https://mastodon.social/@grimler
