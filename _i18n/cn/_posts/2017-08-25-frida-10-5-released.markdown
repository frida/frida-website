---
layout: news_item
title: 'Frida 10.5 发布'
date: 2017-08-25 04:00:00 +0200
author: oleavr
version: 10.5
categories: [release]
---

在 [NowSecure][]，我们一直在熬夜，喝了无数杯咖啡，天哪，这次我们为您带来了新闻。

继续上一版本低级好东西的精神，这次我们将向堆栈上层移动一层。我们将介绍一种使用新 CodeWriter API 的全新方式，使您能够将自己的指令编织到您选择的任何线程执行的机器代码中。我们谈论的是基于每个线程的惰性动态重新编译，并对编译过程进行精确控制。

但首先是一点背景。大多数使用 Frida 的人可能正在使用 [Interceptor][] API 来执行内联 hook，和/或通过 [ObjC][] 和 [Java][] API 进行方法混淆或替换。这个想法通常是修改您期望被调用的一些有趣的 API，并能够将执行转移到您自己的代码，以观察、增强或完全替换应用程序行为。

这种方法的一个缺点是修改了代码或数据，这种更改很容易被插桩到。但这没关系，因为在进行进程内插桩时，对宿主进程自己的代码不可见总是一场猫捉老鼠的游戏。

然而，当试图回答"在这个私有 API 背后，对于给定的输入实际上调用了哪些其他 API？"这个问题时，这些技术非常有限。或者，在进行逆向和模糊测试时，您可能想知道对于给定函数的两个已知输入，执行在哪里出现分歧。另一个例子是测量代码覆盖率。您可以使用 Interceptor 对指令级探针的支持，首先使用静态分析工具找到所有基本块，然后使用 Frida 在各处放置单次探针。

进入 Stalker。这不是一个新的 API，但它允许您做的事情相当有限。把它想象成一个每线程代码跟踪器，其中线程的原始机器代码被动态重新编译到新的内存位置，以便在原始指令之间编织插桩。

它惰性地进行这种重新编译，一次一个基本块。考虑到存在大量自修改代码，它会小心地缓存编译块，以防原始代码在事后发生变化。

Stalker 还不遗余力地重新编译代码，以便副作用是相同的。例如，如果原始指令是 CALL，它将确保推送到堆栈上的是原始下一条指令的地址，而不是下一条重新编译指令的地址。

无论如何，Stalker 历来就像是一个宠物项目中的宠物项目。很有趣，但多年来 Frida 的其他部分引起了我的大部分关注。不过也有一些很棒的例外。多年前，我和 [@karltk][] 坐下来决定让 Stalker 在敌对代码上运行良好时，进行了一些[有趣的结对编程会议][fun pair-programming sessions]。后来我把 [CryptoShark][] 放在一起，为了让人们对其潜力感到兴奋。一段时间过去了，突然 Stalker 收到了由 [Eloi Vanderbeken] 贡献的关键错误修复。今年早些时候，[Antonio Ken Iannillo][] 加入并将其移植到 arm64。然后，就在最近，[Erik Smit][] 出现并修复了一个关键错误，即我们会为 REP 前缀的 JCC 指令生成无效代码。耶！

到目前为止，Stalker 的 API 确实非常有限。您可以告诉它跟踪一个线程，包括您所在的线程，这与内联 hook（即 Interceptor）结合使用非常有用。您唯一能做的两件事是：

1. 告诉它您感兴趣的事件，例如 `call: true`，这将为每个 CALL 指令产生一个事件。这意味着 Stalker 将在每个此类指令之前添加一些日志代码，这将记录 CALL 发生的位置、目标及其堆栈深度。其他事件类型非常相似。
2. 为特定目标添加您自己的调用探针，当对特定目标进行 CALL 时给您一个同步回调到 JavaScript。

我非常兴奋地宣布，我们刚刚介绍了您可以使用此 API 做的第三件事，这是一个游戏规则改变者。您现在可以自定义重新编译过程，而且非常简单：

{% highlight js %}
const appModule = Process.enumerateModulesSync()[0];
const appStart = appModule.base;
const appEnd = appStart.add(appModule.size);

Process.enumerateThreadsSync().forEach(thread => {
  console.log('Stalking ' + thread.id);

  Stalker.follow(thread.id, {
    transform(iterator) {
      const instruction = iterator.next();

      const startAddress = instruction.address;
      const isAppCode = startAddress.compare(appStart) >= 0 &&
          startAddress.compare(appEnd) === -1;

      do {
        if (isAppCode && instruction.mnemonic === 'ret') {
          iterator.putCmpRegI32('eax', 60);
          iterator.putJccShortLabel('jb', 'nope', 'no-hint');

          iterator.putCmpRegI32('eax', 90);
          iterator.putJccShortLabel('ja', 'nope', 'no-hint');

          iterator.putCallout(onMatch);

          iterator.putLabel('nope');
        }

        iterator.keep();
      } while ((instruction = iterator.next()) !== null);
    }
  });
});

function onMatch (context) {
  console.log('Match! pc=' + context.pc +
      ' rax=' + context.rax.toInt32());
}
{% endhighlight %}

每当即将编译新的基本块时，都会同步调用 `transform` 回调。它为您提供了一个迭代器，然后您可以使用它来推动重新编译过程向前发展，一次一条指令。返回的 [Instruction][] 告诉您关于即将重新编译的指令您需要知道的内容。然后您调用 `keep()` 以允许 Stalker 像往常一样重新编译它。这意味着如果您想跳过某些指令，例如因为您已用自己的代码替换了它们，您可以省略此调用。迭代器还允许您插入自己的指令，因为它公开了当前架构的完整 CodeWriter API，例如 [X86Writer][]。

上面的示例确定了应用程序自己的代码在内存中的位置，并在属于应用程序本身的任何代码中的每个 RET 指令之前添加了一些额外的指令。此代码检查 `eax` 是否包含 60 到 90 之间的值，如果是，则调用 JavaScript 以让其实陈任意复杂的逻辑。此回调可以随意读取和修改寄存器。这种方法的好处是您可以将代码插入热代码路径并选择性地调用 JavaScript，从而可以轻松地在机器代码中进行非常快速的检查，但将更复杂的任务卸载到更高级别的语言。您还可以 `Memory.alloc()` 并让生成的代码直接写入那里，而根本不进入 JavaScript。

这就是 10.5 中的大新事物。特别感谢 [@asabil] 帮助塑造了这个新 API。

最后，唯一其他的重大变化是 Instruction API 现在公开了底层 [Capstone][] 指令的更多细节。Stalker 在 x86 和 arm64 上使用的内存也少得多，而且也更可靠。最后，[Process.setExceptionHandler()][] 现在是一个有文档的 API，连同我们的 [SQLite API][]。

享受吧！

[NowSecure]: https://www.nowsecure.com/
[Interceptor]: /docs/javascript-api/#interceptor
[ObjC]: /docs/javascript-api/#objc
[Java]: /docs/javascript-api/#java
[@asabil]: https://twitter.com/asabil
[@karltk]: https://twitter.com/karltk
[fun pair-programming sessions]: http://blog.kalleberg.org/post/833101026/live-x86-code-instrumentation-with-frida
[CryptoShark]: https://www.youtube.com/watch?v=hzDsxtcRavY
[Eloi Vanderbeken]: https://twitter.com/elvanderb
[Antonio Ken Iannillo]: https://twitter.com/AKIannillo
[Erik Smit]: https://github.com/erik-smit
[Instruction]: /docs/javascript-api/#instruction
[X86Writer]: /docs/javascript-api/#x86writer
[Capstone]: http://www.capstone-engine.org/
[Process.setExceptionHandler()]: /docs/javascript-api/#process
[SQLite API]: https://frida.re/docs/javascript-api/#sqlitedatabase
