---
layout: news_item
title: 'Frida 10.4 发布'
date: 2017-08-15 23:00:00 +0200
author: oleavr
version: 10.4
categories: [release]
---

Frida 提供了相当多的构建块，使得跨许多操作系统和架构进行可移植检测变得容易。一个一直缺乏的领域是非可移植用例。虽然我们要提供一些原语，如 *Memory.alloc(Process.pageSize)* 和 *Memory.patchCode()*，使得分配和修改内存中代码成为可能，但没有任何东西可以帮助您实际生成代码。或者将代码从一个内存位置复制到另一个内存位置。

考虑到 Frida 需要为其自身需求生成和转换相当多的机器代码，例如实现 *Interceptor* 和 *Stalker*，我们已经有 C API 来跨六种不同的指令集风格做这些事情也就不足为奇了。最初这些 API 非常简陋，我看不到将它们公开给 JavaScript 的太多价值，但在多年有趣的内部用例之后，它们已经发展到基本部分现在被很好地覆盖的地步。

因此，在 10.4 中，我们终于将所有这些 API 公开给 JavaScript。值得一提的是，这些新绑定是自动生成的，因此未来的添加将毫不费力。

让我们看看 x86 上的一个例子：

{% highlight js %}
const getLivesLeft = Module.getExportByName('game-engine.so',
    'get_lives_left');
const maxPatchSize = 64; // Do not write out of bounds, may be
                         // a temporary buffer!
Memory.patchCode(getLivesLeft, maxPatchSize, code => {
  const cw = new X86Writer(code, { pc: getLivesLeft });
  cw.putMovRegU32('eax', 9999);
  cw.putRet();
  cw.flush();
});
{% endhighlight %}

这意味着我们将目标函数的开头简单地替换为：

{% highlight nasm %}
mov eax, 9999
ret
{% endhighlight %}

即假设返回类型是 `int`，我们只是用 `return 9999;` 替换了函数体。

顺便说一句，您也可以使用 *Memory.protect()* 更改页面保护，然后继续在各处编写代码，但 *Memory.patchCode()* 非常方便，因为它还：

- 确保刷新 CPU 缓存；
- 处理 iOS 上的代码签名边缘情况。

那是一个简单的例子。让我们尝试一些更疯狂的事情：

{% highlight js %}
const multiply = new NativeCallback(function (a, b) {
  return a * b;
}, 'int', ['int', 'int']);

const impl = Memory.alloc(Process.pageSize);

Memory.patchCode(impl, 64, code => {
  const cw = new X86Writer(code, { pc: impl });

  cw.putMovRegU32('eax', 42);

  const stackAlignOffset = Process.pointerSize;
  cw.putSubRegImm('xsp', stackAlignOffset);

  cw.putCallAddressWithArguments(multiply, ['eax', 7]);

  cw.putAddRegImm('xsp', stackAlignOffset);

  cw.putJmpShortLabel('done');

  cw.putMovRegU32('eax', 43);

  cw.putLabel('done');
  cw.putRet();

  cw.flush();
});

const f = new NativeFunction(impl, 'int', []);
console.log(f());
{% endhighlight %}

虽然这只是为了将 *42* 乘以 *7* 而跳了很多圈，但这个想法是为了说明调用函数（甚至回到 JavaScript）和跳转到标签实际上是多么容易。

最后，让我们看看如何将指令从一个内存位置复制到另一个内存位置。正确执行此操作通常比直接 *memcpy()* 复杂得多，因为某些指令与位置相关，需要根据其在内存中的新位置进行调整。让我们看看如何使用 Frida 的新重定位器 API 解决这个问题：

{% highlight js %}
const impl = Memory.alloc(Process.pageSize);

Memory.patchCode(impl, Process.pageSize, code => {
  const cw = new X86Writer(code, { pc: impl });

  const libcPuts = Module.getExportByName(null, 'puts');
  const rl = new X86Relocator(libcPuts, cw);

  while (rl.readOne() !== 0) {
    console.log('Relocating: ' + rl.input.toString());
    rl.writeOne();
  }

  cw.flush();
});

const puts = new NativeFunction(impl, 'int', ['pointer']);
puts(Memory.allocUtf8String('Hello!'));
{% endhighlight %}

我们只用了几行代码就制作了自己的 *puts()* 副本。整洁！

请注意，您还可以插入自己的指令，并使用 *skipOne()* 选择性地跳过指令，以防您想进行自定义检测。（这就是 Stalker 的工作原理。）

无论如何，这就是它的要点。您可以在以下位置找到全新的 API 参考：

- x86
  * [X86Writer](/docs/javascript-api/#x86writer)
  * [X86Relocator](/docs/javascript-api/#x86relocator)
- arm
  * [ArmWriter](/docs/javascript-api/#armwriter)
  * [ArmRelocator](/docs/javascript-api/#armrelocator)
  * [ThumbWriter](/docs/javascript-api/#thumbwriter)
  * [ThumbRelocator](/docs/javascript-api/#thumbrelocator)
- arm64
  * [Arm64Writer](/docs/javascript-api/#arm64writer)
  * [Arm64Relocator](/docs/javascript-api/#arm64relocator)
- mips
  * [MipsWriter](/docs/javascript-api/#mipswriter)
  * [MipsRelocator](/docs/javascript-api/#mipsrelocator)

另请注意，*Process.arch* 对于确定使用哪个 writer/relocator 很方便。关于这一点，您可能想知道为什么 32 位和 64 位 x86 只有一个实现。原因是这些指令集非常接近，以至于拥有统一的实现是有意义的。这也使得编写稍微可移植的代码变得更容易，因为一些元寄存器名称是可用的。例如 `xax` 解析为 `eax` 与 `rax`，具体取决于您所在的进程类型。

享受吧！
