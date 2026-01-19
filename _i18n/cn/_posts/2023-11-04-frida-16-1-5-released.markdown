---
layout: news_item
title: 'Frida 16.1.5 发布'
date: 2023-11-04 21:11:20 +0100
author: oleavr
version: 16.1.5
categories: [release]
---

自上次发布以来，[@hsorbo][] 和我在各种令人兴奋的技术上进行了很多有趣的结对编程。让我们直接潜入。

## Swift

我们为 Swift 引入了一个全新的 ApiResolver，您可以像这样使用它：

{% highlight js %}
const r = new ApiResolver('swift');
r.enumerateMatches('functions:*CoreDevice!*RemoteDevice*')
.forEach(({ name, address }) => {
  console.log('Found:', name, 'at:', address);
});
{% endhighlight %}

还有一个令人兴奋的新 frida-tools 版本 12.3.0，它使用新的 ApiResolver 升级了 frida-trace 以支持 Swift 跟踪：

{% highlight bash %}
$ frida-trace Xcode -y '*CoreDevice!*RemoteDevice*'
{% endhighlight %}

## Module

我们的 Module API 现在还提供 *enumerateSections()* 和 *enumerateDependencies()*。当您想扫描加载的模块以查找特定的部分名称时，我们现有的 *module* ApiResolver 现在可以让您轻松做到这一点：

{% highlight js %}
const r = new ApiResolver('module');
r.enumerateMatches('sections:*!*text*/i')
.forEach(({ name, address }) => {
  console.log('Found:', name, 'at:', address);
});
{% endhighlight %}

## EOF

还有很多其他令人兴奋的更改，所以一定要查看下面的变更日志。

享受吧！

### 变更日志

- swift-api-resolver: 添加全新的 Swift API Resolver。
- module-api-resolver: 支持解析部分。
- api-resolver: 向匹配项添加可选的 *size* 字段。
- module: 添加 enumerate_sections()。
- module: 添加 enumerate_dependencies()。
- device: 添加 unpair()。目前仅针对 iOS 设备实现。
- compiler: 将 frida-compile 升级到 16.4.1，将 @types/frida-gum 升级到 18.4.5。
- gdb: 处理空响应数据包。
- gdb: 处理对功能文档请求的错误回复。
- darwin-mapper: 加载时初始化 TLV 描述符。感谢 [@fabianfreyer][]！
- darwin-module: 添加线程局部变量 API。感谢 [@fabianfreyer][]！
- darwin-module: 稍微优化导出枚举。
- elf-module: 改进部分 ID 生成。
- x86-writer: 添加基于 reg-reg {fs,gs} 的 MOV 指令。感谢 [@fabianfreyer][]！
- arm64-writer: 添加 MRS 指令。感谢 [@fabianfreyer][]！
- arm64-writer: 添加 UBFM, LSL 和 LSR 指令。感谢 [@fabianfreyer][]！
- relocator: 改进 arm64 上的暂存寄存器策略。
- interceptor: 使用计算出的暂存寄存器分支到蹦床。
- interceptor: 在 arm64 上重新定位微小目标。
- linux: 处理禁用的 process_vm_{read,write}v()。感谢 [@Pyraun][]！
- server: 在 rootless iOS 上使用 sysroot 作为临时文件。感谢 [@fabianfreyer][]！
- gumjs: 修复 Interceptor 不存在时 File 和 Database 中的崩溃。感谢 [@mrmacete][]！
- gumjs: 修复 32 位 BE 的 NativePointer from number (#752)。感谢 [@forky2][]！
- gumjs: 将 frida-swift-bridge 升级到 2.0.7。
- ci: 发布 Node.js 20 & 21 以及 Electron 27 的预构建版本。
- ci: 暂时不发布 Swift 绑定。有一个长期存在的 heisenbug 导致 x86_64 切片随机损坏，进而导致 CI 发布作业失败。鉴于使用下载的核心 devkit 在本地构建这些绑定是多么容易，我不太想很快投入时间来解决这个问题，简单地删除发布资产似乎是最好的解决方案。


[@hsorbo]: https://x.com/hsorbo
[@fabianfreyer]: https://github.com/fabianfreyer
[@Pyraun]: https://github.com/Pyraun
[@mrmacete]: https://x.com/bezjaje
[@forky2]: https://github.com/forky2
