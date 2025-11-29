---
layout: news_item
title: 'Frida 16.3.2 发布'
date: 2024-06-04 13:41:24 +0200
author: oleavr
version: 16.3.2
categories: [release]
---

是时候发布另一个错误修复版本了。这里面有不少好东西：

- darwin: 在注入期间避免 thread_set_state()，这样我们就不会在例如 macOS >= 14.5 上被系统杀死。感谢 [@\_saagarjha][] 贡献了修复的初稿！
- fruity: 对需要它的服务执行 RSDCheckin。通过这种方式，当 CoreDevice 隧道可用时，我们保留了 lockdown 服务的 open_channel() 的向后兼容性。
- fruity: 停止缓存 LockdownClient，以避免多个消费者的问题。使用连接了 jailed iOS 设备的 frida-ps 可重现。
- python: 修复 open_service() plist 示例。
- node: 修复未定义值的 spawn() 选项逻辑。感谢 [@as0ler][] 报告并帮助追踪此问题！
- node: 将 aux 选项编组为 GVariant 时跳过 undefined。
- node: 将对象编组为 GVariant 时跳过 undefined。
- node: 处理编组为 GVariant 时的错误。
- node: 修复 openService() plist 示例。

感谢 [@hsorbo][] 在上述所有方面进行有趣且富有成效的结对编程！🙌

注意：由于 CI 问题，此版本从未发布，已在 16.3.3 中解决。


[@_saagarjha]: https://twitter.com/_saagarjha
[@as0ler]: https://twitter.com/as0ler
[@hsorbo]: https://twitter.com/hsorbo
