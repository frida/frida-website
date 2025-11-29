---
layout: news_item
title: 'Frida 17.0.0 发布'
date: 2025-05-17 19:45:49 +0200
author: oleavr
version: 17.0.0
categories: [release]
---

经过无数杯咖啡和有趣的编码会议，[@hsorbo][] 和我很高兴为您带来 Frida 17.0.0。距离上一次主要版本更新已经快三年了，在努力寻找进行破坏性更改的正确时机之后，我们决定终于到时候了。

## Runtime Bridges

困扰我们很长一段时间的主要问题是我们的 runtime bridges，即 frida-{objc,swift,java}-bridge，与 Frida 的 GumJS 运行时捆绑在一起。这带来了一些主要痛点：

- 惯性：受限于 Frida 的发布周期。
- 臃肿：对于不需要特定 runtime bridge 的用户来说。
- 可扩展性：我们希望看到各种运行时的桥接器，但我们添加到 Frida 的越多，我们就越会与惯性和臃肿作斗争。
- 可发现性：社区维护的桥接器更难被发现，因为它们需要不同的消费工作流程。

不过我一直犹豫是否停止捆绑它们，因为要求自定义代理进行构建步骤似乎会增加太多的摩擦。想到会破坏书籍、博客文章、[CodeShare][] 等中的示例，我也感到不安。

摩擦方面是我们早在 [15.2][] 中引入 frida.Compiler API 的原因，同时 frida-tools 发布了一个基于它构建的 CLI 工具 frida-compile。我们的 REPL 也得到了改进，支持直接加载 .ts (TypeScript)，在幕后利用 frida.Compiler。

但这仍然是一个额外的步骤，对于使用 Frida REPL 或 frida-trace 的一次性脚本和早期原型设计工作来说太麻烦了。而且，这会破坏很多例子。为了解决这个问题，刚刚发布的 frida-tools 14.0.0 将这三个桥接器烘焙到其 REPL 和 frida-trace 代理中。

我们的桥接器也已迁移到 ESM，因此它们可以被最新版本的 frida-compile 消费。(感谢 [@yotamN][] 迁移 frida-java-bridge ♥️)

那些从源代码构建 Frida 的人可能还会注意到构建时间的改进。由于我们不再捆绑桥接器，我们终于可以摆脱 Gum 的 frida-compile 依赖，并停止让 Gum 本身依赖 Node.js + npm。

我们仍然有 GumJS 自己的运行时，它实现了诸如 `console.log()` 之类的内置函数，但将其移植到 ESM 并简单地单独烘焙每个模块意味着我们不再需要 JavaScript 打包器。这意味着 Gum 本身的构建时间更快：在 Linux 驱动的 i9-12900K 系统上，构建时间从 ~24s 降至 ~6s。

您可以在 [bridges][] 中查看快速参考教程。

## 传统风格的枚举 API

以前，我们的同步枚举 API 看起来像这样：

{% highlight javascript %}
Process.enumerateModules({
  onMatch(module) {
    console.log(module.name);
  },
  onComplete() {
  }
});
{% endhighlight %}

还有一个等效的 **Sync** 后缀方法，例如此特定示例的 `Process.enumerateModulesSync()`。当时的想法是底层实现可能会变成异步的，但目前大多数都不是，所以 Sync 后缀的实现只是异步外观 API 的一个薄包装。

后来，随着支持的平台越来越多，我意识到所有伪装的异步实现结果总是快速且廉价的操作。所以提供异步风格是没有意义的。对于少数从一开始就真正异步的，比如 `Memory.scan()`，让它们保持这种状态仍然是有意义的。

不过我犹豫是否要破坏 API，所以我选择向每个无后缀实现添加检查，如果省略回调参数，它的行为就像其 Sync 后缀对应物一样。为了让用户迁移出旧式 API，我确保更新我们的 TypeScript 绑定，以便只包含现代风格。

现代风格的等效项如下所示：

{% highlight javascript %}
for (const module of Process.enumerateModules()) {
  console.log(module.name);
}
{% endhighlight %}

其中 `Process.enumerateModules()` 返回 Module 对象数组。

这些传统风格的 API 现在终于消失了。那些用 TypeScript 编写代理的人不需要做任何事情，除非你使用的是我们类型定义的古老版本。

## 内存读/写 API

以前，你会像这样访问内存：

{% highlight javascript %}
const playerHealthLocation = ptr('0x1234');
const playerHealth = Memory.readU32(playerHealthLocation);
Memory.writeU32(playerHealthLocation, 100);
{% endhighlight %}

现代等效项是：

{% highlight javascript %}
const playerHealthLocation = ptr('0x1234');
const playerHealth = playerHealthLocation.readU32();
playerHealthLocation.writeU32(100);
{% endhighlight %}

其中每个写入对应物都返回 NativePointer 本身，以支持链式调用：

{% highlight javascript %}
const playerData = ptr('0x1234');
playerData
    .add(4).writeU32(13)
    .add(4).writeU16(37)
    .add(2).writeU16(42)
    ;
{% endhighlight %}

这些的旧版本现在也消失了，并且只要传统风格的枚举 API 存在，它们就已经从我们的 TypeScript 绑定中消失了。所以这个变化对你们大多数人来说应该也不明显。

## 静态 Module API

现在是破坏性更改，这也影响了在 Frida 17 发布之前使用 TypeScript 绑定的用户。以下静态 Module 方法现在已消失：

- Module.ensureInitialized()
- Module.findBaseAddress()
- Module.getBaseAddress()
- Module.findExportByName()
- Module.getExportByName()
- Module.findSymbolByName()
- Module.getSymbolByName()

这些都很容易迁移。

但首先，让我们涵盖那个奇怪的：

{% highlight javascript %}
Module.getSymbolByName(null, 'open')
{% endhighlight %}

现在这样完成：

{% highlight javascript %}
Module.getGlobalExportByName('open')
{% endhighlight %}

对于其余部分，您首先需要查找 Module，然后访问其上所需的属性或方法。例如，代替：

{% highlight javascript %}
Module.getExportByName('libc.so', 'open')
{% endhighlight %}

新方法是：

{% highlight javascript %}
Process.getModuleByName('libc.so').getExportByName('open')
{% endhighlight %}

Module.getBaseAddress() 的等效项因此是：

{% highlight javascript %}
Process.getModuleByName('libc.so').base
{% endhighlight %}

这意味着现在只有一种进行 Module 自省的方法，并且 API 设计鼓励您编写高性能代码。例如，过去您可能会想这样做：

{% highlight javascript %}
const openImpl = Process.getExportByName('libc.so', 'open');
const readImpl = Process.getExportByName('libc.so', 'read');
{% endhighlight %}

但现在你在做之前可能会三思：

{% highlight javascript %}
const openImpl = Process.getModuleByName('libc.so').getExportByName('open');
const readImpl = Process.getModuleByName('libc.so').getExportByName('read');
{% endhighlight %}

而是这样做：

{% highlight javascript %}
const libc = Process.getModuleByName('libc.so');
const openImpl = libc.getExportByName('open');
const readImpl = libc.getExportByName('read');
{% endhighlight %}

这既更具可读性又更具性能。

最后但并非最不重要的一点是，静态枚举 API，例如 `Module.enumerateExports()`，现在也消失了。然而，这些早在很久以前就从 TypeScript 绑定中删除了，所以你们大多数人应该不需要处理这些。但是如果你这样做了，迁移看起来与上面完全相同。

## EOF

差不多就是这样。祝黑客愉快！


[@hsorbo]: https://twitter.com/hsorbo
[CodeShare]: https://codeshare.frida.re/
[15.2]: /news/2022/07/21/frida-15-2-0-released/
[@yotamN]: https://github.com/yotamN
[bridges]: /docs/bridges
