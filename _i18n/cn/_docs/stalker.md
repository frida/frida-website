## 简介

Stalker 是 Frida 的代码跟踪引擎。它允许跟踪线程,捕获执行的每个函数、每个块,甚至每条指令。
[这里](https://medium.com/@oleavr/anatomy-of-a-code-tracer-b081aadb0df8)提供了对 Stalker 引擎的非常好的概述,
我们建议你先仔细阅读。显然,实现在某种程度上是特定于架构的,尽管它们之间有很多共同之处。
Stalker 目前支持运行 Android 或 iOS 的移动电话和平板电脑上常见的 AArch64 架构,
以及台式机和笔记本电脑上常见的 Intel 64 和 IA-32 架构。本页旨在将事情提升到下一个细节层次,
它剖析了 Stalker 的 ARM64 实现,并更详细地解释了它的工作原理。希望这可以帮助未来将 Stalker 移植到其他硬件架构的工作。

## 免责声明

虽然本文将涵盖 Stalker 内部工作的许多细节,但它不会非常详细地介绍回填(back-patching)。
它旨在作为帮助他人理解该技术的起点,而 Stalker 已经足够复杂了,没有这个!
公平地说,这种复杂性并非没有原因,它是为了最小化本质上是昂贵操作的开销。
最后,虽然本文将涵盖实现的关键概念,并将提取实现的一些关键部分进行逐行分析,
但仍会有一些实现的最后细节留给读者通过阅读[源代码](https://github.com/frida/frida-gum/blob/master/gum/backend-arm64/gumstalker-arm64.c)来发现。
然而,希望它能证明是一个非常有用的起点。

## 目录

  1. [简介](#简介)
  1. [免责声明](#免责声明)
  1. [用例](#用例)
  1. [跟踪](#跟踪)
     1. [gum_stalker_follow_me](#gum_stalker_follow_me)
     1. [gum_stalker_follow](#gum_stalker_follow)
  1. [基本操作](#基本操作)
  1. [选项](#选项)
  1. [术语](#术语)
     1. [探针](#探针)
     1. [信任阈值](#信任阈值)
     1. [排除范围](#排除范围)
     1. [冻结/解冻](#冻结解冻)
     1. [调用指令](#调用指令)
     1. [帧](#帧)
     1. [转换器](#转换器)
     1. [Callouts](#callouts)
     1. [EOB/EOI](#eobeoi)
     1. [序言/尾声](#序言尾声)
     1. [计数器](#计数器)
  1. [Slabs](#slabs)
  1. [块](#块)
  1. [插桩块](#插桩块)
  1. [Helpers](#helpers)
     1. [last_stack_push](#last_stack_push)
     1. [last_stack_pop_and_go](#last_stack_pop_and_go)
  1. [上下文](#上下文)
  1. [上下文 Helpers](#上下文-helpers)
  1. [读取/写入上下文](#读取写入上下文)
  1. [控制流](#控制流)
  1. [Gates](#gates)
  1. [虚拟化函数](#虚拟化函数)
     1. [gum_exec_block_virtualize_branch_insn](#gum_exec_block_virtualize_branch_insn)
     1. [gum_exec_block_virtualize_ret_insn](#gum_exec_block_virtualize_ret_insn)
  1. [发出事件](#发出事件)
  1. [取消跟踪和清理](#取消跟踪和清理)
  1. [杂项](#杂项)
     1. [独占存储](#独占存储)
     1. [耗尽的块](#耗尽的块)
     1. [系统调用虚拟化](#系统调用虚拟化)
     1. [指针认证](#指针认证)
## 简介

Stalker 是 Frida 的代码跟踪引擎。它允许跟踪线程，捕获执行的每个函数、每个块，甚至每条指令。
[这里](https://medium.com/@oleavr/anatomy-of-a-code-tracer-b081aadb0df8)提供了对 Stalker 引擎的非常好的概述，
我们建议你先仔细阅读。显然，实现在某种程度上是特定于架构的，尽管它们之间有很多共同之处。
Stalker 目前支持运行 Android 或 iOS 的移动电话和平板电脑上常见的 AArch64 架构，
以及台式机和笔记本电脑上常见的 Intel 64 和 IA-32 架构。本页旨在将事情提升到下一个细节层次，
它剖析了 Stalker 的 ARM64 实现，并更详细地解释了它的工作原理。希望这可以帮助未来将 Stalker 移植到其他硬件架构的工作。

## 免责声明

虽然本文将涵盖 Stalker 内部工作的许多细节，但它不会非常详细地介绍回填（back-patching）。
它旨在作为帮助他人理解该技术的起点，而 Stalker 已经足够复杂了，没有这个！
公平地说，这种复杂性并非没有原因，它是为了最小化本质上是昂贵操作的开销。
最后，虽然本文将涵盖实现的关键概念，并将提取实现的一些关键部分进行逐行分析，
但仍会有一些实现的最后细节留给读者通过阅读[源代码](https://github.com/frida/frida-gum/blob/master/gum/backend-arm64/gumstalker-arm64.c)来发现。
然而，希望它能证明是一个非常有用的起点。

## 目录

  1. [简介](#简介)
  1. [免责声明](#免责声明)
  1. [用例](#用例)
  1. [跟踪](#跟踪)
     1. [gum_stalker_follow_me](#gum_stalker_follow_me)
     1. [gum_stalker_follow](#gum_stalker_follow)
  1. [基本操作](#基本操作)
  1. [选项](#选项)
  1. [术语](#术语)
     1. [探针](#探针)
     1. [信任阈值](#信任阈值)
     1. [排除范围](#排除范围)
     1. [冻结/解冻](#冻结解冻)
     1. [调用指令](#调用指令)
     1. [帧](#帧)
     1. [转换器](#转换器)
     1. [Callouts](#callouts)
     1. [EOB/EOI](#eobeoi)
     1. [序言/尾声](#序言尾声)
     1. [计数器](#计数器)
  1. [Slabs](#slabs)
  1. [块](#块)
  1. [插桩块](#插桩块)
  1. [Helpers](#helpers)
     1. [last_stack_push](#last_stack_push)
     1. [last_stack_pop_and_go](#last_stack_pop_and_go)
  1. [上下文](#上下文)
  1. [上下文 Helpers](#上下文-helpers)
  1. [读取/写入上下文](#读取写入上下文)
  1. [控制流](#控制流)
  1. [Gates](#gates)
  1. [虚拟化函数](#虚拟化函数)
     1. [gum_exec_block_virtualize_branch_insn](#gum_exec_block_virtualize_branch_insn)
     1. [gum_exec_block_virtualize_ret_insn](#gum_exec_block_virtualize_ret_insn)
  1. [发出事件](#发出事件)
  1. [取消跟踪和清理](#取消跟踪和清理)
  1. [杂项](#杂项)
     1. [独占存储](#独占存储)
     1. [耗尽的块](#耗尽的块)
     1. [系统调用虚拟化](#系统调用虚拟化)
     1. [指针认证](#指针认证)

## 用例

要开始理解 Stalker 的实现，我们必须首先详细了解它为用户提供了什么。
虽然 Stalker 可以通过其原生 Gum 接口直接调用，但大多数用户将通过 [JavaScript API](https://frida.re/docs/javascript-api/#stalker) 调用它，
该 API 将代表他们调用这些 Gum 方法。Gum 的 [TypeScript 类型定义](https://github.com/DefinitelyTyped/DefinitelyTyped/blob/master/types/frida-gum/index.d.ts)有很好的注释，并提供了更多细节。

从 JavaScript 到 Stalker 的主要 API 是：

{% highlight js %}
Stalker.follow([threadId, options])
{% endhighlight %}

> 开始跟踪 `threadId`（如果省略则为当前线程）

让我们考虑何时可以使用这些调用。当你提供线程 ID 进行跟踪时，可能是在你有一个感兴趣的线程并想知道它在做什么的情况下使用。
也许它有一个有趣的名字？可以使用 `cat /proc/PID/tasks/TID/comm` 找到线程名称。
或者你可能使用 Frida JavaScript API `Process.enumerateThreads()` 遍历了进程中的线程，
然后使用 NativeFunction 调用：

{% highlight c %}
int pthread_getname_np(pthread_t thread,
                       char *name, size_t len);
{% endhighlight %}

将此与 [Thread.backtrace()](https://frida.re/docs/javascript-api/#thread) 一起使用来转储线程堆栈，
可以让你真正了解进程在做什么。

你可能调用 `Stalker.follow()` 的另一种情况是从已被[拦截](https://frida.re/docs/javascript-api/#interceptor)或替换的函数中调用。
在这种情况下，你找到了一个感兴趣的函数，并且想了解它的行为方式，你想看看在调用给定函数后线程采用哪些函数或甚至代码块。
也许你想比较代码在不同输入下采用的方向，或者你想修改输入以查看是否可以让代码采用特定路径。

在这两种情况下，虽然 Stalker 必须在底层以稍微不同的方式工作，但它都由相同的简单 API `Stalker.follow()` 为用户管理。

## 跟踪

当用户调用 `Stalker.follow()` 时，在底层，JavaScript 引擎会调用 `gum_stalker_follow_me()` 来跟踪当前线程，
或调用 `gum_stalker_follow(thread_id)` 来跟踪进程中的另一个线程。

### gum_stalker_follow_me

在 `gum_stalker_follow_me()` 的情况下，链接寄存器用于确定开始跟踪的指令。
在 AArch64 架构中，链接寄存器（LR）设置为从函数调用返回后继续执行的指令地址，
它由诸如 BL 和 BLR 之类的指令设置为下一条指令的地址。由于只有一个链接寄存器，
如果被调用的函数要调用另一个例程，则必须存储 LR 的值（通常这将在堆栈上）。
此值随后将从堆栈加载回寄存器，并使用 RET 指令将控制权返回给调用者。

让我们看看 `gum_stalker_follow_me()` 的代码。这是函数原型：

{% highlight c %}
GUM_API void gum_stalker_follow_me (GumStalker * self,
    GumStalkerTransformer * transformer, GumEventSink * sink);
{% endhighlight %}

所以我们可以看到该函数由 QuickJS 或 V8 运行时调用，传递 3 个参数。
第一个是 Stalker 实例本身。请注意，如果一次加载多个脚本，可能会有多个这样的实例。
第二个是转换器，这可以用于在编写插桩代码时转换它（稍后会详细介绍）。
最后一个参数是事件接收器，这是 Stalker 引擎运行时生成的事件传递到的地方。

{% highlight asm %}
#ifdef __APPLE__
  .globl _gum_stalker_follow_me
_gum_stalker_follow_me:
#else
  .globl gum_stalker_follow_me
  .type gum_stalker_follow_me, %function
gum_stalker_follow_me:
#endif
  stp x29, x30, [sp, -16]!
  mov x29, sp
  mov x3, x30
#ifdef __APPLE__
  bl __gum_stalker_do_follow_me
#else
  bl _gum_stalker_do_follow_me
#endif
  ldp x29, x30, [sp], 16
  br x0
{% endhighlight %}

我们可以看到第一条指令 STP 将一对寄存器存储到堆栈上。我们可以注意到表达式 `[sp, -16]!`。
这是一个[预递减](https://thinkingeek.com/2017/05/29/exploring-aarch64-assembler-chapter-8/)，
这意味着首先将堆栈前进 16 字节，然后存储两个 8 字节寄存器值。
我们可以在函数底部看到相应的指令 `ldp x29, x30, [sp], 16`。这是将这两个寄存器值从堆栈恢复到寄存器中。
但这两个寄存器是什么？

嗯，`X30` 是链接寄存器，`X29` 是帧指针寄存器。回想一下，如果我们希望调用另一个函数，
我们必须将链接寄存器存储到堆栈，因为这将导致它被覆盖，我们需要这个值才能返回到我们的调用者。

帧指针用于指向调用函数时堆栈的顶部，以便可以以相对于帧指针的固定偏移量访问所有堆栈传递的参数和基于堆栈的局部变量。
同样，我们需要保存和恢复它，因为每个函数都有自己的这个寄存器的值，所以我们需要存储调用者放入其中的值，
并在返回之前恢复它。实际上，你可以在下一条指令 `mov x29, sp` 中看到我们将帧指针设置为当前堆栈指针。

我们可以看到下一条指令 `mov x3, x30`，将链接寄存器的值放入 X3。
AArch64 上的前 8 个参数在寄存器 X0-X7 中传递。所以这被放入用于第四个参数的寄存器中。
然后我们调用（带链接的分支）函数 `_gum_stalker_do_follow_me()`。
所以我们可以看到我们将前三个参数在 X0-X2 中原封不动地传递，
以便 `_gum_stalker_do_follow_me()` 接收与我们被调用时相同的值。
最后，我们可以看到在此函数返回后，我们分支到我们作为其返回值接收的地址。
（在 AArch64 中，函数的返回值在 X0 中返回）。

{% highlight c %}
gpointer
_gum_stalker_do_follow_me (GumStalker * self,
                           GumStalkerTransformer * transformer,
                           GumEventSink * sink,
                           gpointer ret_addr)
{% endhighlight %}

### gum_stalker_follow

此例程的原型与 `gum_stalker_follow_me()` 非常相似，但有额外的 `thread_id` 参数。
实际上，如果要求跟踪当前线程，那么它将调用该函数。不过让我们看看指定另一个线程 ID 时的情况。

{% highlight c %}
void
gum_stalker_follow (GumStalker * self,
                    GumThreadId thread_id,
                    GumStalkerTransformer * transformer,
                    GumEventSink * sink)
{
  if (thread_id == gum_process_get_current_thread_id ())
  {
    gum_stalker_follow_me (self, transformer, sink);
  }
  else
  {
    GumInfectContext ctx;

    ctx.stalker = self;
    ctx.transformer = transformer;
    ctx.sink = sink;

    gum_process_modify_thread (thread_id, gum_stalker_infect, &ctx);
  }
}
{% endhighlight %}

我们可以看到这调用了函数 `gum_process_modify_thread()`。这不是 Stalker 的一部分，而是 Gum 本身的一部分。
此函数接受一个带有上下文参数的回调来调用，传递线程上下文结构。然后此回调可以修改 `GumCpuContext` 结构，
`gum_process_modify_thread()` 将写回更改。我们可以在下面看到上下文结构，
如你所见，它包含 AArch64 CPU 中所有寄存器的字段。我们还可以在下面看到我们的回调的函数原型。

{% highlight c %}
typedef GumArm64CpuContext GumCpuContext;

struct _GumArm64CpuContext
{
  guint64 pc;
  guint64 sp;

  guint64 x[29];
  guint64 fp;
  guint64 lr;
  guint8 q[128];
};
{% endhighlight %}

{% highlight c %}
static void
gum_stalker_infect (GumThreadId thread_id,
                    GumCpuContext * cpu_context,
                    gpointer user_data)
{% endhighlight %}

那么，`gum_process_modify_thread()` 是如何工作的？嗯，这取决于平台。
在 Linux（和 Android）上，它使用 `ptrace` API（GDB 使用的同一个）来附加到线程并读写寄存器。
但有很多复杂性。在 Linux 上，你不能 ptrace 自己的进程（或实际上同一进程组中的任何进程），
所以 Frida 在其自己的进程组中创建当前进程的克隆并共享相同的内存空间。
它使用 UNIX 套接字与它通信。这个克隆的进程充当调试器，读取原始目标进程的寄存器并将它们存储在共享内存空间中，
然后按需将它们写回进程。哦，还有 `PR_SET_DUMPABLE` 和 `PR_SET_PTRACER`，它们控制谁被允许 ptrace 我们的原始进程的权限。

现在你会看到 `gum_stalker_infect()` 的功能实际上与我们之前提到的 `_gum_stalker_do_follow_me()` 非常相似。
两个函数本质上执行相同的工作，尽管 `_gum_stalker_do_follow_me()` 在目标线程上运行，
但 `gum_stalker_infect()` 不是，所以它必须编写一些代码供目标线程调用，
使用 [GumArm64Writer](https://github.com/frida/frida-gum/blob/master/gum/arch-arm64/gumarm64writer.c) 而不是直接调用函数。

我们将很快更详细地介绍这些函数，但首先我们需要更多的背景知识。
## 基本操作

代码可以被认为是一系列指令块（也称为基本块）。每个块以一系列可选的指令开始（我们可能有两个连续的分支语句），
这些指令按顺序运行，并在我们遇到导致（或可能导致）执行继续使用内存中紧随其后的指令以外的指令时结束。

Stalker 一次处理一个块。它从调用 `gum_stalker_follow_me()` 的返回后的块开始，
或者从调用 `gum_stalker_follow()` 时目标线程的指令指针指向的代码块开始。

Stalker 的工作方式是分配一些内存并向其中写入原始块的新插桩副本。
可以添加指令来生成事件，或执行 Stalker 引擎提供的任何其他功能。
Stalker 还必须根据需要重定位指令。考虑以下指令：

> ADR
> 在 PC 相对偏移处的标签地址。
>
> ADR  Xd, label
>
> Xd
> 是通用目标寄存器的 64 位名称，范围为 0 到 31。
>
> label
> 是要计算其地址的程序标签。
> 它是从此指令地址的偏移量，
> 范围为 ±1MB。

如果将此指令复制到内存中的不同位置并执行，那么因为标签的地址是通过将偏移量添加到当前指令指针来计算的，
所以值会不同。幸运的是，Gum 有一个 [Relocator](https://github.com/frida/frida-gum/blob/master/gum/arch-arm64/gumarm64relocator.c)
正是为了这个目的，它能够根据指令的新位置修改指令，以便计算正确的地址。

现在，回想一下我们说 Stalker 一次处理一个块。那么，我们如何插桩下一个块呢？
我们还记得每个块也以分支指令结束，好吧，如果我们修改这个分支以分支回 Stalker 引擎，
但确保我们存储分支打算结束的目的地，我们可以插桩下一个块并将执行重定向到那里。
这个简单的过程可以一个接一个地继续。

现在，这个过程可能有点慢，所以我们可以应用一些优化。首先，如果我们多次执行同一个代码块
（例如循环，或者只是多次调用的函数），我们不必一遍又一遍地重新插桩它。
我们可以重新执行相同的插桩代码。因此，保留了一个哈希表，其中包含我们之前遇到的所有块以及我们放置块的插桩副本的位置。

其次，当遇到调用指令时，在发出插桩调用后，我们然后发出一个着陆垫（landing pad），
我们可以返回到该着陆垫而无需重新进入 Stalker。Stalker 构建一个侧栈，
使用 `GumExecFrame` 结构记录真实的返回地址（`real_address`）和这个着陆垫（`code_address`）。
当函数返回时，我们发出代码，将检查侧栈中的返回地址与 `real_address` 进行比较，
如果匹配，它可以简单地返回到 `code_address` 而无需重新进入运行时。
这个着陆垫最初将包含进入 Stalker 引擎以插桩下一个块的代码，但稍后可以回填以直接分支到此块。
这意味着整个返回序列可以在不进入和离开 Stalker 的开销的情况下处理。

如果返回地址与 `GumExecFrame` 的 `real_address` 存储的不匹配，或者我们在侧栈中用完空间，
我们只需从头开始构建一个新的。我们需要在应用程序代码执行时保留 LR 的值，
以便应用程序不能使用它来检测 Stalker 的存在（反调试），
或者以防它将其用于除简单返回之外的任何其他目的（例如引用代码段中的内联数据）。
此外，我们希望 Stalker 能够随时取消跟踪，所以我们不想回到我们的堆栈上纠正我们沿途修改的 LR 值。

最后，虽然我们总是用对 Stalker 的调用替换分支以插桩下一个块，
但根据 `Stalker.trustThreshold` 的配置，我们可能会*回填*这样的插桩代码，
用直接分支到下一个插桩块来替换调用。确定性分支（例如目的地是固定的并且分支不是条件的）很简单，
我们可以用一个到下一个块的分支替换到 Stalker 的分支。但我们也可以处理条件分支，
如果我们插桩两个代码块（如果采用分支则为一个，如果不采用则为另一个）。
然后我们可以用一个条件分支替换原始条件分支，该条件分支将控制流引导到采用分支时遇到的块的插桩版本，
然后是到另一个插桩块的无条件分支。我们还可以部分处理目标不是静态的分支。
假设我们的分支是这样的：

{% highlight asm %}
br x0
{% endhighlight %}

这种指令在调用函数指针或类方法时很常见。虽然 X0 的值可以改变，但通常它实际上总是相同的。
在这种情况下，我们可以用将 X0 的值与我们已知的函数进行比较的代码替换最终的分支指令，
如果匹配，则分支到代码的插桩副本的地址。然后可以跟随一个无条件分支回到 Stalker 引擎（如果不匹配）。
所以如果函数指针的值比如说被改变了，那么代码仍然可以工作，我们将重新进入 Stalker 并插桩我们最终到达的任何地方。
但是，如果正如我们所期望的那样它保持不变，那么我们可以完全绕过 Stalker 引擎并直接进入插桩函数。

## 选项

现在让我们看看使用 Stalker 跟踪线程时的选项。当跟踪的线程正在执行时，Stalker 会生成事件，
这些事件被放置到队列中，并定期或由用户手动刷新。这不是由 Stalker 本身完成的，
而是由 `EventSink::process` vfunc 完成的，因为重新进入 JavaScript 运行时一次处理一个事件会非常昂贵。
大小和时间段可以通过选项配置。可以基于每条指令生成事件，用于调用、返回或所有指令。
或者可以基于块生成它们，当块被执行时，或者当它被 Stalker 引擎插桩时。

我们还可以提供两个回调之一 `onReceive` 或 `onCallSummary`。
前者将简单地传递一个包含 Stalker 生成的原始事件的二进制 blob，事件按生成顺序排列。
（`Stalker.parse()` 可用于将其转换为表示事件的元组的 JS 数组。）
第二个聚合这些结果，简单地返回每个函数被调用次数的计数。这比 `onReceive` 更有效，但数据的粒度要低得多。

## 术语

在我们继续描述 Stalker 的详细实现之前，我们首先需要了解设计中使用的一些关键术语和概念。

### 探针

当线程在 Stalker 之外运行时，你可能熟悉使用 `Interceptor.attach()` 在调用给定函数时获得回调。
但是，当线程在 Stalker 中运行时，这些拦截器可能不起作用。这些拦截器通过修补目标函数的前几条指令（序言）
来将执行重定向到 Frida 中来工作。Frida 复制并重定位这些前几条指令到其他地方，
以便在 `onEnter` 回调完成后，它可以将控制流重定向回原始函数。

这些在 Stalker 中可能不起作用的原因很简单，原始函数从未被调用。
每个块在执行之前都在内存中的其他地方插桩，并且执行的是这个副本。
Stalker 支持 API 函数 `Stalker.addCallProbe(address, callback[, data])` 来提供此功能。
如果我们的 `Interceptor` 在块被插桩之前已附加，或者 Stalker 的 `trustThreshold` 配置为我们的块将被重新插桩，
那么我们的 `Interceptor` 将起作用（因为修补的指令将被复制到新的插桩块）。否则它不会。
当然，我们希望能够在不满足这些条件时支持钩子函数。API 的普通用户可能不熟悉设计的这个细节级别，
因此调用探针解决了这个问题。

可选的 data 参数在注册探针回调时传递，并将在执行时传递给回调例程。
因此，此指针需要存储在 Stalker 引擎中。此外，需要存储地址，以便当遇到调用函数的指令时，
可以将代码插桩为首先调用该函数。由于多个函数可能调用你添加探针的函数，
因此许多插桩块可能包含调用探针函数的附加指令。因此，每当添加或删除探针时，
缓存的插桩块都会被销毁，因此所有代码都必须重新插桩。请注意，此 data 参数仅在 `callback` 是 C 回调时使用
——例如使用 `CModule` 实现——因为当使用 JavaScript 时，使用闭包来捕获任何所需的状态更简单。

### 信任阈值

回想一下，我们应用的简单优化之一是，如果我们尝试多次执行一个块，
在后续场合，我们可以简单地调用我们上次创建的插桩块？好吧，这只有在我们正在插桩的代码没有改变的情况下才有效。
在自修改代码的情况下（这通常用作反调试/反反汇编技术，试图阻止对安全关键代码的分析），
代码可能会改变，因此无法重用插桩块。那么，我们如何检测块是否已更改？
我们只需在数据结构中保留原始代码的副本以及插桩版本。然后，当我们再次遇到一个块时，
我们可以将我们要插桩的代码与我们上次插桩的版本进行比较，如果它们匹配，我们可以重用该块。
但是每次块运行时执行比较可能会减慢速度。所以，这又是一个可以自定义 Stalker 的领域。

> `Stalker.trustThreshold`: 一个整数，指定在假定代码可以信任不会变异之前需要执行多少次。
> 指定 -1 表示不信任（慢），0 表示从一开始就信任代码，N 表示在代码执行 N 次后信任代码。默认为 1。

实际上，N 的值是块需要重新执行并与先前插桩的块匹配（例如未更改）的次数，
然后我们才停止执行比较。请注意，即使信任阈值设置为 `-1` 或 `0`，仍会存储代码块的原始副本。
虽然这些值实际上不需要它，但为了保持简单而保留了它。无论如何，这两个都不是默认设置。

### 排除范围

Stalker 还有 API `Stalker.exclude(range)`，它传递一个基址和限制，用于防止 Stalker 插桩这些区域内的代码。
例如，考虑你的线程在 `libc` 内部调用 `malloc()`。你很可能不关心堆的内部工作，
这不仅会降低性能，而且还会生成大量你不关心的无关事件。但是，需要考虑的一件事是，
一旦调用排除范围，该线程的跟踪就会停止，直到它返回。这意味着，如果该线程要调用不在受限范围内的函数，
例如回调，那么 Stalker 将不会捕获它。正如这可以用于停止整个库的跟踪一样，
它也可以用于停止跟踪给定函数（及其被调用者）。如果你的目标应用程序是静态链接的，这可能特别有用。
在这里，我们不能简单地忽略对 `libc` 的所有调用，但我们可以使用 `Module.enumerateSymbols()` 找到 `malloc()` 的符号并忽略该单个函数。

### 冻结/解冻

作为 DEP 的扩展，一些系统防止页面同时标记为可写和可执行。
因此，Frida 必须在可写和可执行之间切换页面权限，以写入插桩代码，并允许该代码分别执行。
当页面可执行时，它们被称为冻结（因为它们不能被更改），当它们再次变为可写时，它们被认为是解冻的。

### 调用指令

与 Intel 不同，AArch64 没有单个显式的 `CALL` 指令，该指令具有不同的形式以应对所有支持的场景。
相反，它使用许多不同的指令来提供对函数调用的支持。这些指令都分支到给定位置并使用返回地址更新链接寄存器 `LR`：

* `BL`
* `BLR`
* `BLRAA`
* `BLRAAZ`
* `BLRAB`
* `BLRABZ`

为简单起见，在本文的其余部分，我们将这些指令集合称为"调用指令"。

### 帧

每当 Stalker 遇到调用时，它都会将返回地址和插桩返回块转发器的地址存储在结构中，
并将这些添加到存储在其自己的数据结构中的堆栈中。它将此用作推测性优化，
并且还用作启发式方法，以在发出调用和返回事件时近似调用深度。

{% highlight c %}
typedef struct _GumExecFrame GumExecFrame;

struct _GumExecFrame
{
  gpointer real_address;
  gpointer code_address;
};
{% endhighlight %}

### 转换器

`GumStalkerTransformer` 类型用于生成插桩代码。默认转换器的实现如下所示：

{% highlight c %}
static void
gum_default_stalker_transformer_transform_block (
    GumStalkerTransformer * transformer,
    GumStalkerIterator * iterator,
    GumStalkerOutput * output)
{
  while (gum_stalker_iterator_next (iterator, NULL))
  {
    gum_stalker_iterator_keep (iterator);
  }
}
{% endhighlight %}

它由负责生成插桩代码的函数 `gum_exec_ctx_obtain_block_for()` 调用，
其工作是生成插桩代码。我们可以看到它使用循环一次处理一条指令。
首先从迭代器检索一条指令，然后告诉 Stalker 按原样插桩指令（不修改）。
这两个函数在 Stalker 本身内部实现。第一个负责解析 `cs_insn` 并更新内部状态。
此 `cs_insn` 类型是内部 [Capstone](http://www.capstone-engine.org/) 反汇编器用于表示指令的数据类型。
第二个负责写出插桩指令（或指令集）。我们稍后将更详细地介绍这些。

用户可以提供自定义实现来替换默认转换器，该实现可以随意替换和插入指令。
[API 文档](https://frida.re/docs/javascript-api/#stalker)中提供了一个很好的示例。

### Callouts

转换器还可以进行 callouts。也就是说，它们指示 Stalker 发出指令以调用 JavaScript 函数
——或纯 C 回调，例如使用 CModule 实现——传递 CPU 上下文和可选的上下文参数。
然后此函数能够随意修改或检查寄存器。此信息存储在 `GumCallOutEntry` 中。

{% highlight c %}
typedef void (* GumStalkerCallout) (GumCpuContext * cpu_context,
    gpointer user_data);

typedef struct _GumCalloutEntry GumCalloutEntry;

struct _GumCalloutEntry
{
  GumStalkerCallout callout;
  gpointer data;
  GDestroyNotify data_destroy;

  gpointer pc;

  GumExecCtx * exec_context;
};
{% endhighlight %}

### EOB/EOI

回想一下，[Relocator](https://github.com/frida/frida-gum/blob/master/gum/arch-arm64/gumarm64relocator.c)
在生成插桩代码中发挥着重要作用。它有两个重要的属性来控制其状态。

块结束（EOB）表示已到达块的末尾。当我们遇到*任何*分支指令时会发生这种情况。分支、调用或返回指令。

输入结束（EOI）表示我们不仅已到达块的末尾，而且可能已到达输入的末尾，
即此指令之后可能不是另一条指令。虽然对于调用指令来说不是这种情况，
因为当被调用者返回时代码控制将（通常）传递回来，因此必须有更多指令跟随。
（请注意，编译器通常会为调用非返回函数（如 `exit()`）生成分支指令。）
虽然不能保证调用指令后有有效指令，但我们可以推测性地优化这种情况。
如果我们遇到非条件分支指令或返回指令，很可能之后不会有代码。

### 序言/尾声

当控制流从程序重定向到 Stalker 引擎时，必须保存 CPU 的寄存器，以便 Stalker 可以运行并使用寄存器，
并在控制传递回程序之前恢复它们，以便不会丢失任何状态。

AArch64 的[过程调用标准](https://static.docs.arm.com/den0024/a/DEN0024A_v8_architecture_PG.pdf)
规定某些寄存器（特别是 X19 到 X29）是被调用者保存的寄存器。
这意味着当编译器生成使用这些寄存器的代码时，它必须首先存储它们。
因此，严格来说没有必要将这些寄存器保存到上下文结构中，因为如果它们被 Stalker 引擎内的代码使用，
它们将被恢复。这个*"最小"*上下文对于大多数目的来说是足够的。

但是，如果 Stalker 引擎要调用由 `Stalker.addCallProbe()` 注册的探针，
或由 `iterator.putCallout()`（由转换器调用）创建的 callout，
那么这些回调将期望接收完整的 CPU 上下文作为参数。
他们将期望能够修改此上下文，并且更改在控制传递回应用程序代码时生效。
因此，对于这些实例，我们必须编写一个*"完整"*上下文，
其布局必须与结构 `GumArm64CpuContext` 规定的预期格式匹配。

{% highlight c %}
typedef struct _GumArm64CpuContext GumArm64CpuContext;

struct _GumArm64CpuContext
{
  guint64 pc;
  guint64 sp; /* X31 */
  guint64 x[29];
  guint64 fp; /* X29 - frame pointer */
  guint64 lr; /* X30 */
  guint8 q[128]; /* FPU, NEON (SIMD), CRYPTO regs */
};
{% endhighlight %}

但是请注意，在任何一种情况下写出必要的 CPU 寄存器（序言）所需的代码都相当长（数十条指令）。
之后恢复它们的代码（尾声）长度相似。我们不想在我们插桩的每个块的开头和结尾写这些。
因此，我们将这些（以与我们编写插桩块相同的方式）写入公共内存位置，
并在每个插桩块的开头和结尾简单地发出调用指令来调用这些函数。
这些公共内存位置称为 *helpers*。以下函数创建这些序言和尾声。

{% highlight c %}
static void gum_exec_ctx_write_minimal_prolog_helper (
    GumExecCtx * ctx, GumArm64Writer * cw);

static void gum_exec_ctx_write_minimal_epilog_helper (
    GumExecCtx * ctx, GumArm64Writer * cw);

static void gum_exec_ctx_write_full_prolog_helper (
    GumExecCtx * ctx, GumArm64Writer * cw);

static void gum_exec_ctx_write_full_epilog_helper (
    GumExecCtx * ctx, GumArm64Writer * cw);
{% endhighlight %}

最后，请注意在 AArch64 架构中，只能直接分支到调用者 ±128 MB 内的代码，
并且使用间接分支更昂贵（在代码大小和性能方面）。因此，随着我们编写越来越多的插桩块，
我们将离共享序言和尾声越来越远。如果我们距离超过 128 MB，
我们只需写出这些序言和尾声的另一个副本以供使用。这给了我们一个非常合理的权衡。

### 计数器

最后，有一系列计数器，你可以看到它们记录在插桩块末尾遇到的每种类型指令的数量。
这些仅由测试套件使用，以在性能调优期间指导开发人员，指示哪些分支类型最常需要完整的上下文切换到 Stalker 以解析目标。
## Slabs

现在让我们看看 Stalker 将其插桩代码存储在哪里,在 slabs 中。
下面是用于保存所有内容的数据结构:

{% highlight c %}
typedef guint8 GumExecBlockFlags;
typedef struct _GumExecBlock GumExecBlock;
typedef struct _GumSlab GumSlab;

struct _GumExecBlock
{
  GumExecCtx * ctx;
  GumSlab * slab;

  guint8 * real_begin;
  guint8 * real_end;
  guint8 * real_snapshot;
  guint8 * code_begin;
  guint8 * code_end;

  GumExecBlockFlags flags;
  gint recycle_count;
};

struct _GumSlab
{
  guint8 * data;
  guint offset;
  guint size;
  GumSlab * next;

  guint num_blocks;
  GumExecBlock blocks[];
};

enum _GumExecBlockFlags
{
  GUM_EXEC_ACTIVATION_TARGET = (1 << 0),
};
{% endhighlight %}

现在让我们看看 Stalker 初始化时配置其大小的一些代码:

{% highlight c %}
#define GUM_CODE_SLAB_MAX_SIZE  (4 * 1024 * 1024)
#define GUM_EXEC_BLOCK_MIN_SIZE 1024

static void
gum_stalker_init (GumStalker * self)
{
  ...

  self->page_size = gum_query_page_size ();
  self->slab_size =
      GUM_ALIGN_SIZE (GUM_CODE_SLAB_MAX_SIZE, self->page_size);
  self->slab_header_size =
      GUM_ALIGN_SIZE (GUM_CODE_SLAB_MAX_SIZE / 12, self->page_size);
  self->slab_max_blocks = (self->slab_header_size -
      G_STRUCT_OFFSET (GumSlab, blocks)) / sizeof (GumExecBlock);

  ...
}
{% endhighlight %}

所以我们可以看到每个 slab 的大小为 4 MB。这个 slab 的 1/12 保留给其头部,
即 `GumSlab` 结构本身,包括其 `GumExecBlock` 数组。请注意,这被定义为 `GumSlab` 结构末尾的零长度数组,
但实际可以放入 slab 头部的这些数量被计算并存储在 `slab_max_blocks` 中。

那么 slab 的其余部分用于什么?虽然 slab 的头部用于所有会计信息,
但 slab 的其余部分(以下称为尾部)用于插桩指令本身(它们内联存储在 slab 中)。

那么为什么将 slab 的 1/12 分配给头部,其余部分分配给指令?
好吧,要插桩的每个块的长度会有很大差异,并且可能会受到所使用的编译器及其优化设置的影响。
一些粗略的经验测试表明,鉴于每个块的平均长度,这可能是一个合理的比率,
以确保我们不会在尾部用完新插桩块的空间之前用完新 `GumExecBlock` 条目的空间,反之亦然。

现在让我们看看创建它们的代码:

{% highlight c %}
static GumSlab *
gum_exec_ctx_add_slab (GumExecCtx * ctx)
{
  GumSlab * slab;
  GumStalker * stalker = ctx->stalker;

  slab = gum_memory_allocate (NULL, stalker->slab_size,
      stalker->page_size,
      stalker->is_rwx_supported ? GUM_PAGE_RWX : GUM_PAGE_RW);

  slab->data = (guint8 *) slab + stalker->slab_header_size;
  slab->offset = 0;
  slab->size = stalker->slab_size - stalker->slab_header_size;
  slab->next = ctx->code_slab;

  slab->num_blocks = 0;

  ctx->code_slab = slab;

  return slab;
}
{% endhighlight %}

在这里,我们可以看到 `data` 字段指向头部之后可以写入指令的尾部的开始。
`offset` 字段跟踪我们在尾部中的偏移量。`size` 字段跟踪尾部中可用的总字节数。
`num_blocks` 字段跟踪已写入 slab 的插桩块数量。

请注意,在可能的情况下,我们使用 RWX 权限分配 slab,这样我们就不必一直冻结和解冻它。
在支持 RWX 的系统上,冻结和解冻函数变为空操作。

最后,我们可以看到每个 slab 都包含一个 `next` 指针,可用于将 slabs 链接在一起形成单链表。
这用于我们可以遍历它们并在 Stalker 完成时处理它们。

## 块

现在我们了解了 slabs 的工作原理。让我们更详细地看看块。
正如我们所知,我们可以在 slab 中存储多个块,并将它们的指令写入尾部。让我们看看分配新块的代码:

{% highlight c %}
static GumExecBlock *
gum_exec_block_new (GumExecCtx * ctx)
{
  GumStalker * stalker = ctx->stalker;
  GumSlab * slab = ctx->code_slab;
  gsize available;

  available = (slab != NULL) ? slab->size - slab->offset : 0;
  if (available >= GUM_EXEC_BLOCK_MIN_SIZE &&
      slab->num_blocks != stalker->slab_max_blocks)
  {
    GumExecBlock * block = slab->blocks + slab->num_blocks;

    block->ctx = ctx;
    block->slab = slab;

    block->code_begin = slab->data + slab->offset;
    block->code_end = block->code_begin;

    block->flags = 0;
    block->recycle_count = 0;

    gum_stalker_thaw (stalker, block->code_begin, available);
    slab->num_blocks++;

    return block;
  }

  if (stalker->trust_threshold < 0 && slab != NULL)
  {
    slab->offset = 0;

    return gum_exec_block_new (ctx);
  }

  gum_exec_ctx_add_slab (ctx);

  gum_exec_ctx_ensure_inline_helpers_reachable (ctx);

  return gum_exec_block_new (ctx);
}
{% endhighlight %}

该函数首先检查 slab 尾部是否有最小大小块的空间(1024 字节),
以及 slab 头部的 `GumExecBlocks` 数组中是否有新条目的空间。
如果有,则在数组中创建一个新条目,并设置其指针以引用 `GumExecCtx`(主 Stalker 会话上下文)和 `GumSlab`。
`code_begin` 和 `code_end` 指针都设置为尾部中的第一个空闲字节。
信任阈值机制使用的 `recycle_count` 用于确定块未修改遇到的次数,重置为零,
并且尾部的其余部分被解冻以允许将代码写入其中。

接下来,如果信任阈值设置为小于零(回想一下 -1 意味着块永远不被信任并且总是重写),
那么我们重置 slab `offset`(指向尾部中第一个空闲字节的指针)并重新开始。
这意味着为 slab 内任何块编写的任何插桩代码都将被覆盖。

最后,由于当前 slab 中没有剩余空间,并且我们不能覆盖它,因为信任阈值意味着块可能会被重用,
那么我们必须通过调用我们上面看到的 `gum_exec_ctx_add_slab()` 来分配一个新的 slab。
然后我们调用 `gum_exec_ctx_ensure_inline_helpers_reachable()`,稍后会详细介绍,
然后我们从新的 slab 分配我们的块。

回想一下,我们使用 *helpers*(例如保存和恢复 CPU 上下文的序言和尾声)
来防止必须在每个块的开头和结尾复制这些指令。由于我们需要能够从我们正在写入 slab 的插桩代码中调用这些,
并且我们使用只能从调用站点到达 ±128 MB 的直接分支来执行此操作,因此我们需要确保我们可以到达它们。
如果我们以前没有写过它们,那么我们将它们写入我们当前的 slab。
请注意,这些 helper 函数需要从 slab 尾部中写入的任何插桩指令中可达。
因为我们的 slab 只有 4 MB 大小,所以如果我们的 helpers 写在我们当前的 slab 中,那么它们将很好地可达。
如果我们正在分配后续 slab 并且它足够接近前一个 slab(我们只保留我们上次写入 helper 函数的位置),
那么我们可能不需要再次写出它们,可以依赖附近 slab 中的先前副本。
请注意,我们受 `mmap()` 的支配,因为我们的 slab 在虚拟内存中的分配位置,
ASLR 可能决定我们的 slab 最终不在前一个附近的任何地方。

我们只能假设这不太可能成为问题,或者这已经被考虑到 slabs 的大小中,
以确保将 helpers 写入每个 slab 不会有太大的开销,因为它不会使用它们空间的很大一部分。
另一种选择可能是每次写出 helper 函数时存储每个位置,以便我们有更多候选者可供选择
(也许我们的 slab 没有分配在先前分配的 slab 附近,但也许它足够接近其他 slab 之一)。
否则,我们可以考虑使用 `mmap()` 制作自定义分配器来保留一个大的(例如 128 MB)虚拟地址空间区域,
然后根据需要再次使用 `mmap()` 一次提交一个 slab 的内存。但这些想法可能都有点过头了。

## 插桩块

插桩代码块的主要函数称为 `gum_exec_ctx_obtain_block_for()`。
它首先在哈希表中查找现有块,该哈希表以插桩的原始块的地址为索引。
如果它找到一个并且满足围绕信任阈值的上述约束,那么它可以简单地返回。

`GumExecBlock` 的字段使用如下。`real_begin` 设置为要插桩的原始代码块的开始。
`code_begin` 字段指向尾部的第一个空闲字节(记住这是由上面讨论的 `gum_exec_block_new()` 函数设置的)。
初始化 `GumArm64Relocator` 以从 `real_begin` 处的原始代码读取代码,
并初始化 `GumArm64Writer` 以将其输出写入从 `code_begin` 开始的 slab。
这些项目中的每一个都打包到 `GumGeneratorContext` 中,最后用于构造 `GumStalkerIterator`。

然后将此迭代器传递给转换器。回想一下默认实现如下:

{% highlight c %}
static void
gum_default_stalker_transformer_transform_block (
    GumStalkerTransformer * transformer,
    GumStalkerIterator * iterator,
    GumStalkerOutput * output)
{
  while (gum_stalker_iterator_next (iterator, NULL))
  {
    gum_stalker_iterator_keep (iterator);
  }
}
{% endhighlight %}

我们现在将略过 `gum_stalker_iterator_next()` 和 `gum_stalker_iterator_keep()` 的细节。
但本质上,这会导致迭代器一次从重定位器读取一条指令的代码,并使用写入器写出重定位的指令。
在此过程之后,可以更新 `GumExecBlock` 结构。其字段 `real_end` 可以设置为重定位器读取到的地址,
其字段 `code_end` 可以设置为写入器写入到的地址。因此 `real_begin` 和 `real_end` 标记原始块的限制,
`code_begin` 和 `code_end` 标记新插桩块的限制。最后,`gum_exec_ctx_obtain_block_for()` 调用 `gum_exec_block_commit()`,
它获取原始块的副本并将其放在插桩副本之后。字段 `real_snapshot` 指向此(因此与 `code_end` 相同)。
接下来,更新 slab 的 `offset` 字段以反映我们的插桩块和原始代码副本使用的空间。最后,冻结块以允许执行它。

{% highlight c %}
static void
gum_exec_block_commit (GumExecBlock * block)
{
  gsize code_size, real_size;

  code_size = block->code_end - block->code_begin;
  block->slab->offset += code_size;

  real_size = block->real_end - block->real_begin;
  block->real_snapshot = block->code_end;
  memcpy (block->real_snapshot, block->real_begin, real_size);
  block->slab->offset += real_size;

  gum_stalker_freeze (block->ctx->stalker, block->code_begin,
      code_size);
}
{% endhighlight %}

现在让我们回到函数 `gum_exec_ctx_obtain_block_for()` 的更多细节。
首先我们应该注意每个块都有一条指令作为前缀。

{% highlight c %}
gum_arm64_writer_put_ldp_reg_reg_reg_offset (cw, ARM64_REG_X16,
    ARM64_REG_X17, ARM64_REG_SP, 16 + GUM_RED_ZONE_SIZE,
    GUM_INDEX_POST_ADJUST);
{% endhighlight %}

此指令是恢复序言(由 `GUM_RESTORATION_PROLOG_SIZE` 表示)。
这在"引导"使用中被跳过——因此你会注意到当返回插桩代码的地址时,
`_gum_stalker_do_follow_me()` 和 `gum_stalker_infect()` 会添加此常量。
但是,当返回指令被插桩时,如果返回到已经插桩的块,那么我们可以简单地返回到该块,
而不是返回到 Stalker 引擎。此代码由 `gum_exec_block_write_ret_transfer_code()` 编写。
在最坏的情况下,我们可能需要使用寄存器来执行到插桩块的最终分支,
此函数将它们存储到堆栈中,并且从堆栈恢复这些的代码在块本身中作为前缀。
因此,如果我们可以直接返回到插桩块,我们将返回到此第一条指令,而不是跳过 `GUM_RESTORATION_PROLOG_SIZE` 字节。

其次,我们可以看到 `gum_exec_ctx_obtain_block_for()` 在插桩块写入后执行以下操作:

{% highlight c %}
gum_arm64_writer_put_brk_imm (cw, 14);
{% endhighlight %}

这插入一个断点指令,旨在简化调试。

最后,如果配置了 Stalker,`gum_exec_ctx_obtain_block_for()` 将在编译块时生成类型为 `GUM_COMPILE` 的事件。

## Helpers

我们可以从 `gum_exec_ctx_ensure_inline_helpers_reachable()` 看到我们总共有 6 个 helpers。
这些 helpers 是我们的插桩块重复需要的常见代码片段。我们不是重复发出它们包含的代码,
而是写一次并放置调用或分支指令让我们的插桩代码执行它。
回想一下,helpers 被写入我们正在写入插桩代码的相同 slabs 中,
如果可能,我们可以重用写入先前附近 slab 的 helper,而不是在每个 slab 中放置副本。

此函数为每个 helper 调用 `gum_exec_ctx_ensure_helper_reachable()`,
后者又调用 `gum_exec_ctx_is_helper_reachable()` 来检查 helper 是否在范围内,
或者调用作为第二个参数传递的回调来写出新副本。

{% highlight c %}
static void
gum_exec_ctx_ensure_inline_helpers_reachable (GumExecCtx * ctx)
{
  gum_exec_ctx_ensure_helper_reachable (ctx,
      &ctx->last_prolog_minimal,
      gum_exec_ctx_write_minimal_prolog_helper);

  gum_exec_ctx_ensure_helper_reachable (ctx,
      &ctx->last_epilog_minimal,
      gum_exec_ctx_write_minimal_epilog_helper);

  gum_exec_ctx_ensure_helper_reachable (ctx,
      &ctx->last_prolog_full,
      gum_exec_ctx_write_full_prolog_helper);

  gum_exec_ctx_ensure_helper_reachable (ctx,
      &ctx->last_epilog_full,
      gum_exec_ctx_write_full_epilog_helper);

  gum_exec_ctx_ensure_helper_reachable (ctx,
      &ctx->last_stack_push,
      gum_exec_ctx_write_stack_push_helper);

  gum_exec_ctx_ensure_helper_reachable (ctx,
      &ctx->last_stack_pop_and_go,
      gum_exec_ctx_write_stack_pop_and_go_helper);
}
{% endhighlight %}

那么,我们的 6 个 helpers 是什么。我们有 2 个用于编写存储寄存器上下文的序言,
一个用于完整上下文,一个用于最小上下文。我们稍后会介绍这些。
我们还有 2 个用于恢复寄存器的相应尾声。另外两个,`last_stack_push` 和 `last_stack_pop_and_go` 在插桩调用指令时使用。

在详细分析这两个之前,我们首先需要了解帧结构。我们可以从下面的代码片段中看到,
我们分配一个页面来包含 `GumExecFrame` 结构。这些结构按顺序存储在页面中,就像一个数组,
并从页面末尾的条目开始填充。每个帧包含原始块的地址和我们生成的用于替换它的插桩块的地址:

{% highlight c %}
typedef struct _GumExecFrame GumExecFrame;
typedef struct _GumExecCtx GumExecCtx;

struct _GumExecFrame
{
  gpointer real_address;
  gpointer code_address;
};

struct _GumExecCtx
{
  ...
  GumExecFrame * current_frame;
  GumExecFrame * first_frame;
  GumExecFrame * frames;
  ...
};

static GumExecCtx *
gum_stalker_create_exec_ctx (GumStalker * self,
                             GumThreadId thread_id,
                             GumStalkerTransformer * transformer,
                             GumEventSink * sink)
{
  ...

  ctx->frames = gum_memory_allocate (
      NULL, self->page_size, self->page_size, GUM_PAGE_RW);
  ctx->first_frame = (GumExecFrame *) ((guint8 *) ctx->frames +
      self->page_size - sizeof (GumExecFrame));
  ctx->current_frame = ctx->first_frame;

  ...

  return ctx;
}
{% endhighlight %}

### last_stack_push

理解 Stalker 和特别是 helpers 的大部分复杂性在于,
一些函数——让我们称它们为写入器——编写稍后执行的代码。
这些写入器本身有分支,确定要编写的确切代码,并且编写的代码有时也可以有分支。
因此,我对这两个 helpers 采取的方法是显示将发出到 slab 中的汇编的伪代码,
该代码将由插桩块调用。

此 helper 的伪代码如下所示:

{% highlight c %}
void
last_stack_push_helper (gpointer x0,
                        gpointer x1)
{
  GumExecFrame ** x16 = &ctx->current_frame
  GumExecFrame * x17 = *x16
  gpointer x2 = x17 & (ctx->stalker->page_size - 1)
  if x2 != 0:
    x17--
    x17->real_address = x0
    x17->code_address = x1
    *x16 = x17
  return
}
{% endhighlight %}

正如我们所看到的,这个 helper 实际上是一个简单的函数,它接受两个参数,
要存储在下一个 `GumExecFrame` 结构中的 `real_address` 和 `code_address`。
请注意,我们的堆栈从它们存储的页面末尾向开始向后写入,
并且 `current_frame` 指向最后使用的条目(所以我们的堆栈是满的和递减的)。
还要注意,我们有一个条件检查来查看我们是否在最后一个条目上
(页面最开始的那个将是页面对齐的),如果我们用完了更多条目的空间(我们有 512 个空间),
那么我们什么也不做。如果我们有空间,我们将参数中的值写入条目,
并延迟 `current_frame` 指针以指向它。

此 helper 在*虚拟化*调用指令时使用。虚拟化是给替换指令(通常是与分支相关的指令)
的名称,用一系列指令代替执行预期块,允许 Stalker 管理控制流。
回想一下,当我们的转换器使用迭代器遍历指令并调用 `iterator.keep()` 时,
我们输出转换后的指令。当我们遇到分支时,我们需要发出代码以回调到 Stalker 引擎,
以便它可以插桩该块,但如果分支语句是调用指令(`BL`、`BLX` 等),
我们还需要发出对上述 helper 的调用以存储堆栈帧信息。
此信息在发出调用事件时使用,以及稍后在优化返回时使用。

### last_stack_pop_and_go

现在让我们看看 `last_stack_pop_and_go` helper。要理解这一点,
我们还需要了解 `gum_exec_block_write_ret_transfer_code()`(调用它的代码)编写的代码,
以及它调用的 `gum_exec_block_write_exec_generated_code()` 编写的代码。
我们现在将跳过指针认证。

{% highlight c %}
void
ret_transfer_code (arm64_reg ret_reg)
{
  gpointer x16 = ret_reg
  goto last_stack_pop_and_go_helper
}

void
last_stack_pop_and_go_helper (gpointer x16)
{
  GumExecFrame ** x0 = &ctx->current_frame
  GumExecFrame * x1 = *x0
  gpointer x17 = x0.real_address
  if x17 == x16:
    x17 = x0->code_address
    x1++
    *x0 = x1
    goto x17
  else:
    x1 = ctx->first_frame
    *x0 = x1
    gpointer * x0 = &ctx->return_at
    *x0 = x16
    last_prologue_minimal()
    x0 = &ctx->return_at
    x1 = *x0
    gum_exec_ctx_replace_current_block_from_ret(ctx, x1)
    last_epilogue_minimal()
    goto exec_generated_code
}

void
exec_generated_code (void)
{
  gpointer * x16 = &ctx->resume_at
  gpointer x17 = *x16
  goto x17
}
{% endhighlight %}

所以这段代码有点难。它实际上不是一个函数,实际的汇编由于需要保存和恢复寄存器而有点混乱。
但它的本质是:当虚拟化返回指令时,此 helper 用于优化将控制权传递回调用者。
ret_reg 包含我们打算返回到的块的地址。

让我们看看返回指令的定义:

> RET
> 从子例程返回,无条件分支到寄存器中的地址,
> 并提示这是子例程返回。
>
> RET  {Xn}
> 其中:
>
> Xn
> 是保存要分支到的地址的通用寄存器的 64 位名称,
> 范围为 0 到 31。如果不存在,则默认为 X30。

正如我们所看到的,我们将返回到寄存器中传递的地址。
通常,我们可以预测寄存器值以及我们将返回到哪里,
因为编译器将发出汇编代码,以便将寄存器设置为紧跟在将我们带到那里的调用之后的指令的地址。
在发出插桩调用后,我们直接在其后发出一个小着陆垫,它将回调到 Stalker 以插桩下一个块。
稍后可以回填此着陆垫(如果条件合适)以避免完全重新进入 Stalker。
我们将原始块的地址和调用后的此着陆垫存储在 `GumExecFrame` 结构中,
因此我们可以简单地通过用简单分支到此着陆垫的指令替换返回指令来虚拟化我们的返回指令。
我们不需要每次看到返回指令时都重新进入 Stalker 引擎,并获得不错的性能提升。简单!

但是,我们必须记住,并非所有调用都会导致返回。
敌对或专用代码的常见技术是进行调用以使用 `LR` 来确定指令指针的当前位置。
然后可以将此值用于内省目的(例如验证代码以检测修改、解密或解扰代码等)。

此外,请记住用户可以使用自定义转换来随意修改指令,
他们可以插入修改寄存器值的指令,或者可能是传递上下文结构的 callout 函数,
允许他们随意修改寄存器值。现在考虑如果他们修改返回寄存器中的值会怎样!

所以我们可以看到 helper 检查返回寄存器的值与 `GumExecFrame` 中存储的 `real_address` 的值。
如果匹配,那么一切都很好,我们可以简单地直接分支回着陆垫。
回想一下,在第一个实例中,这只是重新进入 Stalker 以插桩下一个块并分支到它,
但在稍后的时间点,可以使用回填直接分支到此插桩块并避免完全重新进入 Stalker。

否则,我们遵循不同的路径。首先清除 `GumExecFrame` 数组,
现在我们的控制流已经偏离,我们将再次开始构建我们的堆栈。
我们接受,如果我们曾经返回到它们,我们将为到目前为止记录的调用堆栈中的任何先前帧采取相同的较慢路径,
但将有可能为我们从这里遇到的新调用使用快速路径(直到下次以非常规方式使用调用指令)。

我们制作一个最小序言(我们的插桩代码现在将不得不重新进入 Stalker),
我们需要能够在将控制权返回给它之前恢复应用程序的寄存器。
我们调用返回的入口门 `gum_exec_ctx_replace_current_block_from_ret()`(稍后会详细介绍入口门)。
然后我们在分支到 `ctx->resume_at` 指针之前执行相应的尾声,
该指针在上述对 `gum_exec_ctx_replace_current_block_from_ret()` 的调用期间由 Stalker 设置为指向新的插桩块。
## 上下文

现在让我们看看序言和尾声。

{% highlight c %}
static void
gum_exec_ctx_write_prolog (GumExecCtx * ctx,
                           GumPrologType type,
                           GumArm64Writer * cw)
{
  gpointer helper;

  helper = (type == GUM_PROLOG_MINIMAL)
      ? ctx->last_prolog_minimal
      : ctx->last_prolog_full;

  gum_arm64_writer_put_stp_reg_reg_reg_offset (cw, ARM64_REG_X19,
      ARM64_REG_LR, ARM64_REG_SP, -(16 + GUM_RED_ZONE_SIZE),
      GUM_INDEX_PRE_ADJUST);
  gum_arm64_writer_put_bl_imm (cw, GUM_ADDRESS (helper));
}

static void
gum_exec_ctx_write_epilog (GumExecCtx * ctx,
                           GumPrologType type,
                           GumArm64Writer * cw)
{
  gpointer helper;

  helper = (type == GUM_PROLOG_MINIMAL)
      ? ctx->last_epilog_minimal
      : ctx->last_epilog_full;

  gum_arm64_writer_put_bl_imm (cw, GUM_ADDRESS (helper));
  gum_arm64_writer_put_ldp_reg_reg_reg_offset (cw, ARM64_REG_X19,
      ARM64_REG_X20, ARM64_REG_SP, 16 + GUM_RED_ZONE_SIZE,
      GUM_INDEX_POST_ADJUST);
}
{% endhighlight %}

我们可以看到，除了调用相应的序言或尾声 helpers 之外，这些并没有做太多事情。
我们可以看到序言将 `X19` 和链接寄存器存储到堆栈中。
然后在尾声结束时将这些恢复到 `X19` 和 `X20` 中。
这是因为 `X19` 需要作为暂存空间来写入上下文块，并且需要保留链接寄存器，因为它会被 helper 调用破坏。

LDP 和 STP 指令分别加载和存储一对寄存器，并可以选择增加或减少堆栈指针。
这种增加或减少可以在值加载或存储之前或之后进行。

还要注意放置这些寄存器的偏移量。它们存储在堆栈顶部之外的 `16` 字节 + `GUM_RED_ZONE_SIZE` 处。
请注意，我们在 AArch64 上的堆栈是满的和递减的。这意味着堆栈向较低地址增长，
堆栈指针指向最后推入的项目（而不是下一个空白空间）。
因此，如果我们从堆栈指针中减去 16 个字节，那么这给了我们足够的空间来存储两个 64 位寄存器。
请注意，堆栈指针必须在存储之前递减（预递减）并在加载之后递增（后递增）。

那么 `GUM_RED_ZONE_SIZE` 是什么？
[redzone](http://hungri-yeti.com/2015/10/19/the-arm64-aarch64-stack/) 是堆栈指针之外的 128 字节区域，
函数可以使用它来存储临时变量。这允许函数在堆栈中存储数据，而无需一直调整堆栈指针。
请注意，对序言的此调用可能是我们插桩块中执行的第一件事，
我们不知道应用程序代码在 redzone 中存储了什么局部变量，
因此在开始使用堆栈存储 Stalker 引擎的信息之前，我们必须确保将堆栈指针推进到它之外。

## 上下文 Helpers

既然我们已经了解了如何调用这些 helpers，现在让我们看看 helpers 本身。
虽然有两个序言和两个尾声（完整和最小），但它们都由同一个函数编写，因为它们有很多共同点。
编写的版本基于函数参数。展示这些最简单的方法是使用带注释的代码：

{% highlight c %}
static void
gum_exec_ctx_write_prolog_helper (GumExecCtx * ctx,
                                  GumPrologType type,
                                  GumArm64Writer * cw)
{
  // 跟踪我们推送到堆栈上的内容，因为我们将要在执行上下文中存储原始应用程序堆栈的位置。
  // 目前对我们 helper 的调用已经跳过了 red zone 并存储了 LR 和 X19。
  gint immediate_for_sp = 16 + GUM_RED_ZONE_SIZE;

  // 此指令用于将 CPU 标志存储到 X15 中。
  const guint32 mrs_x15_nzcv = 0xd53b420f;

  // 请注意，只有完整的序言必须看起来像 C 结构定义，
  // 因为这是传递给 callouts 等的数据结构。

  // 将返回地址保存到 X19 中的插桩块。我们将全程保留它，并在最后分支回那里。
  // 这将带我们回到由 gum_exec_ctx_write_prolog() 编写的代码
  gum_arm64_writer_put_mov_reg_reg (cw, ARM64_REG_X19, ARM64_REG_LR);

  // LR = SP[8] 将前一个块（或用户代码）的返回地址保存在 LR 中。
  // 这是由 gum_exec_ctx_write_prolog() 编写的代码推送到那里的。
  // 一旦我们返回到我们的插桩代码块，这就是将保留在 LR 中的那个。
  // 注意 SP+8 的使用在入口（序言）上有点不对称，因为它用于传递 LR。
  // 在出口（尾声）上，它用于传递 X20，因此 gum_exec_ctx_write_epilog() 在那里恢复它。
  gum_arm64_writer_put_ldr_reg_reg_offset (cw,
      ARM64_REG_LR, ARM64_REG_SP, 8);

  // 存储 SP[8] = X20。我们已经读取了由 gum_exec_ctx_write_prolog() 放在那里的 LR 的值，
  // 并正在那里写入 X20，以便它可以由 gum_exec_ctx_write_epilog() 编写的代码恢复
  gum_arm64_writer_put_str_reg_reg_offset (cw,
      ARM64_REG_X20, ARM64_REG_SP, 8);

  if (type == GUM_PROLOG_MINIMAL)
  {
    // 存储所有 FP/NEON 寄存器。NEON 是 ARM 核心上的 SIMD 引擎，
    // 允许一次对多个输入执行操作。
    gum_arm64_writer_put_push_reg_reg (cw,
        ARM64_REG_Q6, ARM64_REG_Q7);

    gum_arm64_writer_put_push_reg_reg (cw,
        ARM64_REG_Q4, ARM64_REG_Q5);

    gum_arm64_writer_put_push_reg_reg (cw,
        ARM64_REG_Q2, ARM64_REG_Q3);

    gum_arm64_writer_put_push_reg_reg (cw,
        ARM64_REG_Q0, ARM64_REG_Q1);

    immediate_for_sp += 4 * 32;

    // X29 是帧指针
    // X30 是链接寄存器
    gum_arm64_writer_put_push_reg_reg (cw,
        ARM64_REG_X29, ARM64_REG_X30);

    // 我们在这里使用 STP 推送成对的寄存器。实际上我们要推送奇数个，
    // 所以我们只是推送 STALKER_REG_CTX 作为填充来凑数
    /* X19 - X28 是被调用者保存的寄存器 */

    // 如果我们只调用编译的 C 代码，那么编译器将确保如果函数使用寄存器 X19 到 X28，
    // 那么它们的值将被保留。因此，我们不需要在这里存储它们，因为它们不会被修改。
    // 但是，如果我们进行 callout，那么我们希望 Stalker 最终用户能够看到完整的寄存器集，
    // 并能够对它们进行任何他们认为合适的修改。
    gum_arm64_writer_put_push_reg_reg (cw,
        ARM64_REG_X18, ARM64_REG_X30);
    gum_arm64_writer_put_push_reg_reg (cw,
        ARM64_REG_X16, ARM64_REG_X17);
    gum_arm64_writer_put_push_reg_reg (cw,
        ARM64_REG_X14, ARM64_REG_X15);
    gum_arm64_writer_put_push_reg_reg (cw,
        ARM64_REG_X12, ARM64_REG_X13);
    gum_arm64_writer_put_push_reg_reg (cw,
        ARM64_REG_X10, ARM64_REG_X11);
    gum_arm64_writer_put_push_reg_reg (cw,
        ARM64_REG_X8, ARM64_REG_X9);
    gum_arm64_writer_put_push_reg_reg (cw,
        ARM64_REG_X6, ARM64_REG_X7);
    gum_arm64_writer_put_push_reg_reg (cw,
        ARM64_REG_X4, ARM64_REG_X5);
    gum_arm64_writer_put_push_reg_reg (cw,
       ARM64_REG_X2, ARM64_REG_X3);
    gum_arm64_writer_put_push_reg_reg (cw,
       ARM64_REG_X0, ARM64_REG_X1);
    immediate_for_sp += 11 * 16;
  }
  else if (type == GUM_PROLOG_FULL)
  {
    /* GumCpuContext.q[128] */
    gum_arm64_writer_put_push_reg_reg (cw,
        ARM64_REG_Q6, ARM64_REG_Q7);
    gum_arm64_writer_put_push_reg_reg (cw,
        ARM64_REG_Q4, ARM64_REG_Q5);
    gum_arm64_writer_put_push_reg_reg (cw,
        ARM64_REG_Q2, ARM64_REG_Q3);
    gum_arm64_writer_put_push_reg_reg (cw,
        ARM64_REG_Q0, ARM64_REG_Q1);

    /* GumCpuContext.x[29] + fp + lr + padding */
    // X29 是帧指针
    // X30 是链接寄存器
    // X15 再次被推送仅用于填充
    gum_arm64_writer_put_push_reg_reg (cw,
        ARM64_REG_X30, ARM64_REG_X15);
    gum_arm64_writer_put_push_reg_reg (cw,
        ARM64_REG_X28, ARM64_REG_X29);
    gum_arm64_writer_put_push_reg_reg (cw,
        ARM64_REG_X26, ARM64_REG_X27);
    gum_arm64_writer_put_push_reg_reg (cw,
        ARM64_REG_X24, ARM64_REG_X25);
    gum_arm64_writer_put_push_reg_reg (cw,
        ARM64_REG_X22, ARM64_REG_X23);
    gum_arm64_writer_put_push_reg_reg (cw,
        ARM64_REG_X20, ARM64_REG_X21);

    // 将 X19（当前持有此函数要返回的 LR 值，即由 gum_exec_ctx_write_prolog() 编写的调用者的地址）
    // 暂时存储在 X20 中。我们已经推送了 X20，所以我们可以自由使用它，
    // 但我们想将应用程序的 X19 值推入上下文。
    // 这是由 gum_exec_ctx_write_prolog() 中的代码推送到堆栈上的，
    // 所以我们可以在推送之前从那里恢复它。
    gum_arm64_writer_put_mov_reg_reg (cw,
        ARM64_REG_X20, ARM64_REG_X19);

    // 在调用 helper 之前，从序言推送的值恢复 X19。
    gum_arm64_writer_put_ldr_reg_reg_offset (cw,
        ARM64_REG_X19, ARM64_REG_SP,
        (6 * 16) + (4 * 32));

    // 推送应用程序的 X18 和 X19 值。X18 未修改。我们上面已经更正了 X19。
    gum_arm64_writer_put_push_reg_reg (cw,
        ARM64_REG_X18, ARM64_REG_X19);

    // 从 X20 恢复 X19
    gum_arm64_writer_put_mov_reg_reg (cw,
        ARM64_REG_X19, ARM64_REG_X20);

    gum_arm64_writer_put_push_reg_reg (cw,
        ARM64_REG_X16, ARM64_REG_X17);
    gum_arm64_writer_put_push_reg_reg (cw,
        ARM64_REG_X14, ARM64_REG_X15);
    gum_arm64_writer_put_push_reg_reg (cw,
        ARM64_REG_X12, ARM64_REG_X13);
    gum_arm64_writer_put_push_reg_reg (cw,
        ARM64_REG_X10, ARM64_REG_X11);
    gum_arm64_writer_put_push_reg_reg (cw,
        ARM64_REG_X8, ARM64_REG_X9);
    gum_arm64_writer_put_push_reg_reg (cw,
        ARM64_REG_X6, ARM64_REG_X7);
    gum_arm64_writer_put_push_reg_reg (cw,
        ARM64_REG_X4, ARM64_REG_X5);
    gum_arm64_writer_put_push_reg_reg (cw,
        ARM64_REG_X2, ARM64_REG_X3);
    gum_arm64_writer_put_push_reg_reg (cw,
        ARM64_REG_X0, ARM64_REG_X1);

    /* GumCpuContext.pc + sp */

    // 我们将在这里存储 PC 和 SP。PC 设置为零，对于 SP，
    // 我们必须在存储所有这些上下文信息之前计算原始 SP。
    // 注意我们在这里使用零寄存器（AArch64 中的一个特殊寄存器，总是具有值 0）。
    gum_arm64_writer_put_mov_reg_reg (cw,
        ARM64_REG_X0, ARM64_REG_XZR);
    gum_arm64_writer_put_add_reg_reg_imm (cw,
        ARM64_REG_X1, ARM64_REG_SP,
        (16 * 16) + (4 * 32) + 16 + GUM_RED_ZONE_SIZE);
    gum_arm64_writer_put_push_reg_reg (cw,
        ARM64_REG_X0, ARM64_REG_X1);

    immediate_for_sp += sizeof (GumCpuContext) + 8;
  }

  // 将算术逻辑单元标志存储到 X15 中。虽然看起来上面用于计算原始堆栈指针的 add 指令可能已经更改了标志，
  // 但 AArch64 有一个不修改条件标志的 ADD 指令，以及一个修改条件标志的 ADDS 指令。
  gum_arm64_writer_put_instruction (cw, mrs_x15_nzcv);

  /* 方便地将 X20 指向保存的寄存器的开头 */
  // X20 稍后由诸如 gum_exec_ctx_load_real_register_from_full_frame_into() 之类的函数使用，
  // 以发出引用保存帧的代码。
  gum_arm64_writer_put_mov_reg_reg (cw, ARM64_REG_X20, ARM64_REG_SP);

  /* padding + status */
  // 这会推送标志以确保在 Stalker 内部执行后可以正确恢复它们。
  gum_arm64_writer_put_push_reg_reg (cw,
      ARM64_REG_X14, ARM64_REG_X15);
  immediate_for_sp += 1 * 16;

  // 我们在入口处将 LR 保存到 X19 中，以便在此 helper 运行后我们可以分支回插桩代码。
  // 虽然插桩代码调用了我们，但在调用 helper 之前，我们将 LR 恢复到了其先前的值（应用程序代码）。
  // 虽然 LR 不是被调用者保存的（例如，在返回时保存和恢复它不是我们的责任，而是我们调用者的责任），
  // 但在这里这样做是为了最小化插桩块中内联存根的代码大小。
  gum_arm64_writer_put_br_reg_no_auth (cw, ARM64_REG_X19);
}
{% endhighlight %}

现在让我们看看尾声：

{% highlight c %}
static void
gum_exec_ctx_write_epilog_helper (GumExecCtx * ctx,
                                  GumPrologType type,
                                  GumArm64Writer * cw)
{
  // 此指令用于将 X15 的值恢复回 ALU 标志。
  const guint32 msr_nzcv_x15 = 0xd51b420f;

  /* padding + status */
  // 注意我们还没有恢复标志，因为我们必须等到完成所有可能修改标志的操作（例如加法、减法等）。
  // 但是，我们必须在将 X15 恢复回其原始值之前这样做。
  gum_arm64_writer_put_pop_reg_reg (cw,
      ARM64_REG_X14, ARM64_REG_X15);

  if (type == GUM_PROLOG_MINIMAL)
  {
    // 将 LR 保存在 X19 中，以便我们可以返回到插桩块中的调用者。
    // 请注意，我们必须在返回之前将链接寄存器 X30 恢复回其原始值（应用程序代码中的块）。
    // 这在下面执行。回想一下，我们的 X19 值由内联序言本身保存到堆栈中，
    // 并由我们要返回的内联序言恢复。所以我们可以继续在这里将其用作暂存空间。
    gum_arm64_writer_put_mov_reg_reg (cw,
        ARM64_REG_X19, ARM64_REG_LR);

    /* restore status */
    // 我们已经完成了所有可能改变标志的指令。
    gum_arm64_writer_put_instruction (cw, msr_nzcv_x15);

    // 恢复我们在上下文中保存的所有寄存器。我们早些时候推送了 X30 作为填充，
    // 但我们将在紧接着弹出 X30 的实际推送值之前将其弹回那里。
    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_X0, ARM64_REG_X1);
    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_X2, ARM64_REG_X3);
    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_X4, ARM64_REG_X5);
    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_X6, ARM64_REG_X7);
    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_X8, ARM64_REG_X9);
    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_X10, ARM64_REG_X11);
    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_X12, ARM64_REG_X13);
    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_X14, ARM64_REG_X15);
    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_X16, ARM64_REG_X17);
    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_X18, ARM64_REG_X30);
    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_X29, ARM64_REG_X30);

    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_Q0, ARM64_REG_Q1);
    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_Q2, ARM64_REG_Q3);
    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_Q4, ARM64_REG_Q5);
    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_Q6, ARM64_REG_Q7);
  }
  else if (type == GUM_PROLOG_FULL)
  {
    /* GumCpuContext.pc + sp */
    // 我们将堆栈指针和 PC 存储在堆栈中，但我们不想将 PC 恢复回用户代码，
    // 并且我们的堆栈指针应该自然恢复，因为推送到其上的所有数据都被弹回。
    gum_arm64_writer_put_add_reg_reg_imm (cw,
        ARM64_REG_SP, ARM64_REG_SP, 16);

    /* restore status */
    // 同样，既然上述加法已经完成，我们已经完成了任何影响标志的操作。
    gum_arm64_writer_put_instruction (cw, msr_nzcv_x15);

    /* GumCpuContext.x[29] + fp + lr + padding */
    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_X0, ARM64_REG_X1);
    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_X2, ARM64_REG_X3);
    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_X4, ARM64_REG_X5);
    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_X6, ARM64_REG_X7);
    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_X8, ARM64_REG_X9);
    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_X10, ARM64_REG_X11);
    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_X12, ARM64_REG_X13);
    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_X14, ARM64_REG_X15);
    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_X16, ARM64_REG_X17);
    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_X18, ARM64_REG_X19);
    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_X20, ARM64_REG_X21);

    // 回想一下，X19 和 X20 实际上是由尾声本身恢复的，
    // 因为 X19 在序言/尾声 helpers 期间用作暂存空间，而 X20 被序言重新用作指向上下文结构的指针。
    // 如果我们有一个完整的序言，那么这意味着它是为了我们可以进入一个 callout，
    // 允许 Stalker 最终用户检查和修改所有寄存器。这意味着对上面上下文结构中寄存器的任何更改必须在运行时反映出来。
    // 因此，由于这些值是由尾声从堆栈的更高处恢复的，我们必须用上下文结构中的值覆盖那里的值。
    gum_arm64_writer_put_stp_reg_reg_reg_offset (cw, ARM64_REG_X19,
        ARM64_REG_X20, ARM64_REG_SP, (5 * 16) + (4 * 32),
        GUM_INDEX_SIGNED_OFFSET);

    // 将 LR 保存在 X19 中，以便我们可以返回到插桩代码中的调用者。
    // 请注意，我们必须在返回之前将链接寄存器 X30 恢复回其原始值。
    // 这在下面执行。回想一下，我们的 X19 值由内联序言本身保存到堆栈中，
    // 并由我们要返回的内联尾声恢复。
    gum_arm64_writer_put_mov_reg_reg (cw,
        ARM64_REG_X19, ARM64_REG_LR);

    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_X22, ARM64_REG_X23);
    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_X24, ARM64_REG_X25);
    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_X26, ARM64_REG_X27);
    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_X28, ARM64_REG_X29);

    // 回想一下，在构建序言时，X15 也作为填充与 X30 一起被推送。
    // 但是，Stalker 最终用户可以修改上下文，从而修改 X15 的值。
    // 然而，这不会影响作为填充存储在这里的重复项，因此 X15 将被破坏。
    // 因此，在从堆栈恢复两个寄存器之前，我们将现在恢复的 X15 值复制到存储此副本以进行填充的位置。
    gum_arm64_writer_put_str_reg_reg_offset (cw,
        ARM64_REG_X15, ARM64_REG_SP, 8);
    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_X30, ARM64_REG_X15);

    /* GumCpuContext.q[128] */
    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_Q0, ARM64_REG_Q1);
    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_Q2, ARM64_REG_Q3);
    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_Q4, ARM64_REG_Q5);
    gum_arm64_writer_put_pop_reg_reg (cw,
        ARM64_REG_Q6, ARM64_REG_Q7);
  }

  // 现在我们可以返回到我们的调用者（尾声的内联部分），LR 仍然设置为应用程序代码的原始值。
  gum_arm64_writer_put_br_reg_no_auth (cw, ARM64_REG_X19)
}
{% endhighlight %}

这都很复杂。部分原因是我们只有一个寄存器用作暂存空间，
部分原因是我们希望将存储在插桩块中的内联序言和尾声代码保持在最低限度，
部分原因是因为我们的上下文值可以被 callouts 等更改。但希望现在这一切都有意义。

## 读取/写入上下文

既然我们已经保存了上下文，无论是完整上下文还是最小上下文，
Stalker 可能需要从上下文中读取寄存器以查看应用程序代码的状态。
例如，查找分支或返回指令将要分支到的地址，以便我们可以插桩该块。

当 Stalker 编写序言和尾声代码时，它通过调用 `gum_exec_block_open_prolog()` 和 `gum_exec_block_close_prolog()` 来完成。
这些将已编写的序言类型存储在 `gc->opened_prolog` 中。

{% highlight c %}
static void
gum_exec_block_open_prolog (GumExecBlock * block,
                            GumPrologType type,
                            GumGeneratorContext * gc)
{
  if (gc->opened_prolog >= type)
    return;

  /* 出于性能原因，我们不想处理这种情况 */
  g_assert (gc->opened_prolog == GUM_PROLOG_NONE);

  gc->opened_prolog = type;

  gum_exec_ctx_write_prolog (block->ctx, type, gc->code_writer);
}

static void
gum_exec_block_close_prolog (GumExecBlock * block,
                             GumGeneratorContext * gc)
{
  if (gc->opened_prolog == GUM_PROLOG_NONE)
    return;

  gum_exec_ctx_write_epilog (block->ctx, gc->opened_prolog,
      gc->code_writer);

  gc->opened_prolog = GUM_PROLOG_NONE;
}
{% endhighlight %}

因此，当我们想要读取寄存器时，这可以通过单个函数 `gum_exec_ctx_load_real_register_into()` 来实现。
这确定正在使用哪种序言并相应地调用相关例程。请注意，这些例程实际上并不读取寄存器，它们发出读取它们的代码。

{% highlight c %}
static void
gum_exec_ctx_load_real_register_into (GumExecCtx * ctx,
                                      arm64_reg target_register,
                                      arm64_reg source_register,
                                      GumGeneratorContext * gc)
{
  if (gc->opened_prolog == GUM_PROLOG_MINIMAL)
  {
    gum_exec_ctx_load_real_register_from_minimal_frame_into (ctx,
        target_register, source_register, gc);
    return;
  }
  else if (gc->opened_prolog == GUM_PROLOG_FULL)
  {
    gum_exec_ctx_load_real_register_from_full_frame_into (ctx,
        target_register, source_register, gc);
    return;
  }

  g_assert_not_reached ();
}
{% endhighlight %}

从完整帧读取寄存器实际上是最简单的。我们可以看到代码与用于将上下文传递给 callouts 等的结构紧密匹配。
请记住，在每种情况下，寄存器 `X20` 都指向上下文结构的基址。

{% highlight c %}
typedef GumArm64CpuContext GumCpuContext;

struct _GumArm64CpuContext
{
  guint64 pc;
  guint64 sp;

  guint64 x[29];
  guint64 fp;
  guint64 lr;
  guint8 q[128];
};

static void
gum_exec_ctx_load_real_register_from_full_frame_into (
    GumExecCtx * ctx,
    arm64_reg target_register,
    arm64_reg source_register,
    GumGeneratorContext * gc)
{
  GumArm64Writer * cw;

  cw = gc->code_writer;

  if (source_register >= ARM64_REG_X0 &&
      source_register <= ARM64_REG_X28)
  {
    gum_arm64_writer_put_ldr_reg_reg_offset (cw,
        target_register, ARM64_REG_X20,
        G_STRUCT_OFFSET (GumCpuContext, x) +
        ((source_register - ARM64_REG_X0) * 8));
  }
  else if (source_register == ARM64_REG_X29)
  {
    gum_arm64_writer_put_ldr_reg_reg_offset (cw,
        target_register, ARM64_REG_X20,
        G_STRUCT_OFFSET (GumCpuContext, fp));
  }
  else if (source_register == ARM64_REG_X30)
  {
    gum_arm64_writer_put_ldr_reg_reg_offset (cw,
        target_register, ARM64_REG_X20,
        G_STRUCT_OFFSET (GumCpuContext, lr));
  }
  else
  {
    gum_arm64_writer_put_mov_reg_reg (cw,
        target_register, source_register);
  }
}
{% endhighlight %}

从最小上下文读取实际上有点难。`X0` 到 `X18` 很简单，它们存储在上下文块中。
`X18` 之后是 8 字节填充（总共 10 对寄存器），然后是 `X29` 和 `X30`。这总共有 11 对寄存器。
紧随其后的是 NEON/浮点寄存器（总共 128 字节）。最后 `X19` 和 `X20` 存储在此之上，
因为它们由 `gum_exec_ctx_write_epilog()` 编写的内联尾声代码恢复。

{% highlight c %}
static void
gum_exec_ctx_load_real_register_from_minimal_frame_into (
    GumExecCtx * ctx,
    arm64_reg target_register,
    arm64_reg source_register,
    GumGeneratorContext * gc)
{
  GumArm64Writer * cw;

  cw = gc->code_writer;

  if (source_register >= ARM64_REG_X0 &&
      source_register <= ARM64_REG_X18)
  {
    gum_arm64_writer_put_ldr_reg_reg_offset (cw,
        target_register, ARM64_REG_X20,
        (source_register - ARM64_REG_X0) * 8);
  }
  else if (source_register == ARM64_REG_X19 ||
      source_register == ARM64_REG_X20)
  {
    gum_arm64_writer_put_ldr_reg_reg_offset (cw,
        target_register, ARM64_REG_X20,
        (11 * 16) + (4 * 32) +
        ((source_register - ARM64_REG_X19) * 8));
  }
  else if (source_register == ARM64_REG_X29 ||
      source_register == ARM64_REG_X30)
  {
    gum_arm64_writer_put_ldr_reg_reg_offset (cw,
        target_register, ARM64_REG_X20,
        (10 * 16) + ((source_register - ARM64_REG_X29) * 8));
  }
  else
  {
    gum_arm64_writer_put_mov_reg_reg (cw,
        target_register, source_register);
  }
}
{% endhighlight %}

## 控制流

Stalker 的执行从 3 个入口点之一开始：

* `_gum_stalker_do_follow_me()`
* `gum_stalker_infect()`
* `gum_exec_ctx_replace_current_block_with()`

前两个我们已经介绍过了，它们初始化 Stalker 引擎并开始插桩第一个执行块。
`gum_exec_ctx_replace_current_block_with()` 用于插桩后续块。
事实上，此函数与前两个函数的主要区别在于 Stalker 引擎已经初始化，因此不需要重复此工作。
这三个都调用 `gum_exec_ctx_obtain_block_for()` 来生成插桩块。

我们之前在转换器部分介绍了 `gum_exec_ctx_obtain_block_for()`。
它调用正在使用的转换实现，默认情况下调用 `gum_stalker_iterator_next()`，
后者使用 `gum_arm64_relocator_read_one()` 调用重定位器以读取下一条重定位指令。
然后它调用 `gum_stalker_iterator_keep()` 来生成插桩副本。
它在一个循环中执行此操作，直到 `gum_stalker_iterator_next()` 返回 `FALSE`，因为它已到达块的末尾。

大多数时候 `gum_stalker_iterator_keep()` 将简单地调用 `gum_arm64_relocator_write_one()` 来按原样发出重定位指令。
但是，如果指令是分支或返回指令，它将分别调用 `gum_exec_block_virtualize_branch_insn()` 或 `gum_exec_block_virtualize_ret_insn()`。
我们将稍后更详细地介绍这两个虚拟化函数，它们发出代码以通过入口门将控制权转移回 `gum_exec_ctx_replace_current_block_with()`，
准备处理下一个块（除非有优化可以让我们绕过 Stalker 并直接进入下一个插桩块，或者我们正在进入排除范围）。

## Gates

入口门（Entry gates）由宏生成，每个在块末尾找到的不同指令类型都有一个。
当我们虚拟化每种类型的指令时，我们通过这些门之一将控制流引导回 `gum_exec_ctx_replace_current_block_with()` 函数。
我们可以看到门的实现非常简单，它更新已被调用的次数计数器，
并将控制权传递给 `gum_exec_ctx_replace_current_block_with()`，
传递它被调用时的参数、`GumExecCtx` 和要插桩的下一个块的 `start_address`。

{% highlight c %}
static gboolean counters_enabled = FALSE;
static guint total_transitions = 0;

#define GUM_ENTRYGATE(name) \
  gum_exec_ctx_replace_current_block_from_##name
#define GUM_DEFINE_ENTRYGATE(name) \
  static guint total_##name##s = 0; \
  \
  static gpointer GUM_THUNK \
  GUM_ENTRYGATE (name) ( \
      GumExecCtx * ctx, \
      gpointer start_address) \
  { \
    if (counters_enabled) \
      total_##name##s++; \
    \
    return gum_exec_ctx_replace_current_block_with (ctx, \
        start_address); \
  }
#define GUM_PRINT_ENTRYGATE_COUNTER(name) \
  g_printerr ("\t" G_STRINGIFY (name) "s: %u\n", total_##name##s)
{% endhighlight %}

这些计数器可以通过以下例程显示。它们仅供测试套件使用，而不是通过 API 暴露给用户。

{% highlight c %}
#define GUM_PRINT_ENTRYGATE_COUNTER(name) \
  g_printerr ("\t" G_STRINGIFY (name) "s: %u\n", total_##name##s)

void
gum_stalker_dump_counters (void)
{
  g_printerr ("\n\ntotal_transitions: %u\n", total_transitions);

  GUM_PRINT_ENTRYGATE_COUNTER (call_imm);
  GUM_PRINT_ENTRYGATE_COUNTER (call_reg);
  GUM_PRINT_ENTRYGATE_COUNTER (post_call_invoke);
  GUM_PRINT_ENTRYGATE_COUNTER (excluded_call_imm);
  GUM_PRINT_ENTRYGATE_COUNTER (excluded_call_reg);
  GUM_PRINT_ENTRYGATE_COUNTER (ret);

  GUM_PRINT_ENTRYGATE_COUNTER (jmp_imm);
  GUM_PRINT_ENTRYGATE_COUNTER (jmp_reg);

  GUM_PRINT_ENTRYGATE_COUNTER (jmp_cond_cc);
  GUM_PRINT_ENTRYGATE_COUNTER (jmp_cond_cbz);
  GUM_PRINT_ENTRYGATE_COUNTER (jmp_cond_cbnz);
  GUM_PRINT_ENTRYGATE_COUNTER (jmp_cond_tbz);
  GUM_PRINT_ENTRYGATE_COUNTER (jmp_cond_tbnz);

  GUM_PRINT_ENTRYGATE_COUNTER (jmp_continuation);
}
{% endhighlight %}

## 虚拟化函数

现在让我们更详细地看看我们用于替换在每个块末尾找到的分支指令的*虚拟化*。
我们有四个这样的函数：

* `gum_exec_block_virtualize_branch_insn()`
* `gum_exec_block_virtualize_ret_insn()`
* `gum_exec_block_virtualize_sysenter_insn()`
* `gum_exec_block_virtualize_linux_sysenter()`

我们可以看到其中两个与系统调用有关（实际上，一个调用另一个），我们稍后会介绍这些。
让我们看看用于分支和返回的那些。

### gum_exec_block_virtualize_branch_insn

此例程首先确定分支的目的地是来自指令中的立即偏移量还是寄存器。
在后者的情况下，我们还不能提取值，我们只确定哪个寄存器。这被称为 `target`。
函数的下一部分处理分支指令。这包括条件和非条件分支。
对于条件目标，如果不采用分支，则目的地称为 `cond_target`，这设置为原始块中下一条指令的地址。

同样，`regular_entry_func` 和 `cond_entry_func` 用于保存将用于处理分支的入口门。
前者用于保存用于非条件分支的门，`cond_entry_func` 保存用于条件分支的门（无论是否采用）。

函数 `gum_exec_block_write_jmp_transfer_code()` 用于编写分支到入口门所需的代码。
对于非条件分支，这很简单，我们调用传递 `target` 和 `regular_entry_func` 的函数。
对于条件分支，事情稍微复杂一些。我们的输出类似于以下伪代码：

{% highlight c %}
  INVERSE_OF_ORIGINAL_BRANCH(is_false)
  jmp_transfer_code(target, cond_entry_func)
is_false:
  jmp_transfer_code(cond_target, cond_entry_func)
{% endhighlight %}

在这里，我们可以看到我们首先将分支指令写入我们的插桩块，
就像在我们的插桩块中一样，我们还需要确定是否应该采用分支。
但我们不是直接分支到目标，就像对于非条件分支一样，
我们使用 `gum_exec_block_write_jmp_transfer_code()` 编写代码，
通过相关的入口门跳回 Stalker，传递我们要分支到的真实地址。
但请注意，分支与原始分支反转（例如 `CBZ` 将被 `CBNZ` 替换）。

现在，让我们看看 `gum_exec_block_virtualize_branch_insn()` 如何处理调用。
首先，如果我们配置为生成调用事件，我们会发出代码来生成调用事件。
接下来我们检查是否有任何探针在使用中。如果有，那么我们调用 `gum_exec_block_write_call_probe_code()`
来发出调用任何注册的探针回调所需的代码。接下来，我们检查调用是否针对排除范围
（注意我们只能在调用是针对立即地址时才能这样做），如果是，那么我们按原样发出指令。
但是，我们随后使用 `gum_exec_block_write_jmp_transfer_code()`，
就像我们在处理分支时所做的那样，发出代码以在返回地址处回调到 Stalker 以插桩块。
请注意，这里我们使用 `excluded_call_imm` 入口门。

最后，如果它只是一个普通的调用表达式，那么我们使用函数 `gum_exec_block_write_call_invoke_code()` 来发出处理调用的代码。
由于所有回填优化，此函数相当复杂，因此我们只看基础知识。

还记得之前在 `gum_exec_block_virtualize_branch_insn()` 中，
我们只能在目标在立即数中指定时检查我们的调用是否针对排除范围吗？
好吧，如果目标是在寄存器中指定的，那么在这里我们发出代码来检查目标是否在排除范围内。
这是通过使用 `gum_exec_ctx_write_push_branch_target_address()` 加载目标寄存器
（这反过来调用我们之前介绍的 `gum_exec_ctx_load_real_register_into()` 来读取上下文）
并发出代码来调用 `gum_exec_block_check_address_for_exclusion()` 来完成的，其实现非常不言自明。
如果它被排除，则采用分支，并使用与上面讨论的处理排除的立即调用时描述的类似代码。

接下来我们发出代码来调用入口门并生成被调用者的插桩块。
然后调用 helper `last_stack_push` 将我们的 `GumExecFrame` 添加到我们的上下文中，其中包含原始和插桩块地址。
真实和插桩代码地址分别从 GeneratorContext 和 CodeWriter 的当前光标位置读取，
然后我们为返回地址生成所需的着陆垫（这是我们之前介绍的优化，
我们可以在执行虚拟化返回语句时直接跳到此块，而不是重新进入 Stalker）。
最后，我们使用 `gum_exec_block_write_exec_generated_code()` 发出代码以分支到插桩的被调用者。

### gum_exec_block_virtualize_ret_insn

在查看了调用指令的虚拟化之后，你会很高兴知道这个相对简单！
如果配置了，此函数调用 `gum_exec_block_write_ret_event_code()` 来为返回语句生成事件。
然后它调用 `gum_exec_block_write_ret_transfer_code()` 来生成处理返回指令所需的代码。
这也太简单了，它发出代码来调用我们之前介绍的 `last_stack_pop_and_go` helper。
## 发出事件

事件是 Stalker 引擎的关键输出之一。它们由以下函数发出。它们的实现同样非常不言自明：

* `gum_exec_ctx_emit_call_event()`
* `gum_exec_ctx_emit_ret_event()`
* `gum_exec_ctx_emit_exec_event()`
* `gum_exec_ctx_emit_block_event()`

然而，这些函数中每一个都需要注意的一点是，它们都调用 `gum_exec_block_write_unfollow_check_code()`
来生成检查 Stalker 是否要停止跟踪的代码。我们接下来将更详细地看看这个。

## 取消跟踪和清理

如果我们查看生成插桩代码以检查我们是否被要求取消跟踪的函数，我们可以看到它导致线程调用
`gum_exec_ctx_maybe_unfollow()`，传递要插桩的下一条指令的地址。
我们可以看到，如果状态已设置为停止跟踪，那么我们只需分支回原始代码。

{% highlight c %}
static void
gum_exec_block_write_unfollow_check_code (GumExecBlock * block,
                                          GumGeneratorContext * gc,
                                          GumCodeContext cc)
{
  GumExecCtx * ctx = block->ctx;
  GumArm64Writer * cw = gc->code_writer;
  gconstpointer beach = cw->code + 1;
  GumPrologType opened_prolog;

  if (cc != GUM_CODE_INTERRUPTIBLE)
    return;

  gum_arm64_writer_put_call_address_with_arguments (cw,
      GUM_ADDRESS (gum_exec_ctx_maybe_unfollow), 2,
      GUM_ARG_ADDRESS, GUM_ADDRESS (ctx),
      GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->begin));
  gum_arm64_writer_put_cbz_reg_label (cw, ARM64_REG_X0, beach);

  opened_prolog = gc->opened_prolog;
  gum_exec_block_close_prolog (block, gc);
  gc->opened_prolog = opened_prolog;

  gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X16,
      GUM_ADDRESS (&ctx->resume_at));
  gum_arm64_writer_put_ldr_reg_reg_offset (cw,
      ARM64_REG_X17, ARM64_REG_X16, 0);
  gum_arm64_writer_put_br_reg_no_auth (cw, ARM64_REG_X17);

  gum_arm64_writer_put_label (cw, beach);
}

static gboolean
gum_exec_ctx_maybe_unfollow (GumExecCtx * ctx,
                             gpointer resume_at)
{
  if (g_atomic_int_get (&ctx->state) !=
      GUM_EXEC_CTX_UNFOLLOW_PENDING)
    return FALSE;

  if (ctx->pending_calls > 0)
    return FALSE;

  gum_exec_ctx_unfollow (ctx, resume_at);

  return TRUE;
}

static void
gum_exec_ctx_unfollow (GumExecCtx * ctx,
                       gpointer resume_at)
{
  ctx->current_block = NULL;

  ctx->resume_at = resume_at;

  gum_tls_key_set_value (ctx->stalker->exec_ctx, NULL);

  ctx->destroy_pending_since = g_get_monotonic_time ();
  g_atomic_int_set (&ctx->state, GUM_EXEC_CTX_DESTROY_PENDING);
}
{% endhighlight %}

关于挂起调用的简要说明。如果我们调用排除范围，那么我们在插桩代码中发出原始调用，然后回调到 Stalker。
然而，当线程在排除范围内运行时，我们无法控制指令指针，直到它返回。
因此，我们只需要跟踪这些并等待线程退出排除范围。

现在我们可以看到运行线程如何优雅地回到运行正常的未插桩代码，让我们看看我们首先如何停止跟踪。
我们有两种可能的方法来停止跟踪：

* `gum_stalker_unfollow_me()`
* `gum_stalker_unfollow()`

第一个很简单，我们将状态设置为停止跟踪。然后调用 `gum_exec_ctx_maybe_unfollow()`
尝试停止跟踪当前线程，然后处理 Stalker 上下文。

{% highlight c %}
void
gum_stalker_unfollow_me (GumStalker * self)
{
  GumExecCtx * ctx;

  ctx = gum_stalker_get_exec_ctx (self);
  if (ctx == NULL)
    return;

  g_atomic_int_set (&ctx->state, GUM_EXEC_CTX_UNFOLLOW_PENDING);

  if (!gum_exec_ctx_maybe_unfollow (ctx, NULL))
    return;

  g_assert (ctx->unfollow_called_while_still_following);

  gum_stalker_destroy_exec_ctx (self, ctx);
}
{% endhighlight %}

我们在这里注意到我们将 `NULL` 作为地址传递给 `gum_exec_ctx_maybe_unfollow()`，这看起来可能很奇怪，
但我们可以看到在这种情况下它没有被使用，因为当我们插桩一个块时
（记住 `gum_exec_ctx_replace_current_block_with()` 是入口门引导我们插桩后续块的地方）
我们检查是否即将调用 `gum_unfollow_me()`，如果是，那么我们从函数返回原始块，
而不是 `gum_exec_ctx_obtain_block_for()` 生成的插桩块的地址。
因此我们可以看到这是一个特殊情况，此函数未被跟踪。我们只是跳到真实函数，
所以此时我们已经永远停止跟踪该线程。这种处理与排除范围不同，
因为对于那些范围，我们在插桩块中保留原始调用指令，但随后跟随回调到 Stalker。
在这种情况下，我们只是跳转回原始未插桩块：

{% highlight c %}
static gpointer gum_unfollow_me_address;

static void
gum_stalker_class_init (GumStalkerClass * klass)
{
  ...
  gum_unfollow_me_address = gum_strip_code_pointer (
      gum_stalker_unfollow_me);
  ...
}

static gpointer
gum_exec_ctx_replace_current_block_with (GumExecCtx * ctx,
                                         gpointer start_address)
{
  ...

  if (start_address == gum_unfollow_me_address ||
      start_address == gum_deactivate_address)
  {
    ctx->unfollow_called_while_still_following = TRUE;
    ctx->current_block = NULL;
    ctx->resume_at = start_address;
  }
  ...

  else
  {
    ctx->current_block = gum_exec_ctx_obtain_block_for (ctx,
        start_address, &ctx->resume_at);

    ...
  }

  return ctx->resume_at;

  ...
}
{% endhighlight %}

现在让我们看看 `gum_stalker_unfollow()`：

{% highlight c %}
void
gum_stalker_unfollow (GumStalker * self,
                      GumThreadId thread_id)
{
  if (thread_id == gum_process_get_current_thread_id ())
  {
    gum_stalker_unfollow_me (self);
  }
  else
  {
    GSList * cur;

    GUM_STALKER_LOCK (self);

    for (cur = self->contexts; cur != NULL; cur = cur->next)
    {
      GumExecCtx * ctx = (GumExecCtx *) cur->data;

      if (ctx->thread_id == thread_id &&
          g_atomic_int_compare_and_exchange (&ctx->state,
              GUM_EXEC_CTX_ACTIVE,
              GUM_EXEC_CTX_UNFOLLOW_PENDING))
      {
        GUM_STALKER_UNLOCK (self);

        if (!gum_exec_ctx_has_executed (ctx))
        {
          GumDisinfectContext dc;

          dc.exec_ctx = ctx;
          dc.success = FALSE;

          gum_process_modify_thread (thread_id,
              gum_stalker_disinfect, &dc);

          if (dc.success)
            gum_stalker_destroy_exec_ctx (self, ctx);
        }

        return;
      }
    }

    GUM_STALKER_UNLOCK (self);
  }
}
{% endhighlight %}

此函数查看上下文列表，查找请求线程的上下文。再次，它将上下文的状态设置为 `GUM_EXEC_CTX_UNFOLLOW_PENDING`。
如果线程已经运行，我们必须等待它检查此标志并返回正常执行。
但是，如果它尚未运行（也许当我们要求跟踪它时它处于阻塞系统调用中，并且从未在第一时间被感染），
那么我们可以通过调用 `gum_process_modify_thread()` 来修改线程上下文（此函数前面已详细描述）
并使用 `gum_stalker_disinfect()` 作为我们的回调来执行更改，从而自己*消毒*它。
这只是检查程序计数器是否设置为指向 `infect_thunk`，并将程序指针重置回其原始值。
`infect_thunk` 由 `gum_stalker_infect()` 创建，这是 `gum_stalker_follow()` 用于修改上下文的回调。
回想一下，虽然一些设置可以代表目标线程进行，但有些必须在目标线程本身的上下文中完成
（特别是在线程本地存储中设置变量）。好吧，正是 `infect_thunk` 包含该代码。

## 杂项

希望我们现在已经涵盖了 Stalker 最重要的方面，并对其工作原理提供了良好的背景。
不过，我们还有一些其他观察结果可能会引起兴趣。

### 独占存储

AArch64 架构支持[独占加载/存储指令](https://static.docs.arm.com/100934/0100/armv8_a_synchronization_primitives_100934_0100_en.pdf)。
这些指令旨在用于同步。如果从给定地址执行独占加载，然后尝试对同一位置进行独占存储，
那么 CPU 能够检测在此期间对同一位置的任何其他存储（独占或其他），并且存储失败。

显然，这些类型的原语很可能用于互斥锁和信号量等结构。
多个线程可能会尝试加载信号量的当前计数，测试它是否已满，然后递增并将新值存回以获取信号量。
这些独占操作非常适合这种情况。但是考虑如果多个线程竞争同一资源会发生什么。
如果其中一个线程被 Stalker 跟踪，它将总是输掉比赛。
此外，这些指令很容易被其他类型的 CPU 操作干扰，因此如果我们做一些复杂的事情，
比如在加载和存储之间发出事件，我们将导致它每次都失败，并最终无限循环。
然而，Stalker 处理这种情况：

{% highlight c %}
gboolean
gum_stalker_iterator_next (GumStalkerIterator * self,
                           const cs_insn ** insn)
{

  ...

    switch (instruction->ci->id)
    {
      case ARM64_INS_STXR:
      case ARM64_INS_STXP:
      case ARM64_INS_STXRB:
      case ARM64_INS_STXRH:
      case ARM64_INS_STLXR:
      case ARM64_INS_STLXP:
      case ARM64_INS_STLXRB:
      case ARM64_INS_STLXRH:
        gc->exclusive_load_offset = GUM_INSTRUCTION_OFFSET_NONE;
        break;
      default:
        break;
    }

    if (gc->exclusive_load_offset != GUM_INSTRUCTION_OFFSET_NONE)
    {
      gc->exclusive_load_offset++;
      if (gc->exclusive_load_offset == 4)
        gc->exclusive_load_offset = GUM_INSTRUCTION_OFFSET_NONE;
    }
  }

  ...
  ...
}

void
gum_stalker_iterator_keep (GumStalkerIterator * self)
{
  ...

  switch (insn->id)
  {
    case ARM64_INS_LDAXR:
    case ARM64_INS_LDAXP:
    case ARM64_INS_LDAXRB:
    case ARM64_INS_LDAXRH:
    case ARM64_INS_LDXR:
    case ARM64_INS_LDXP:
    case ARM64_INS_LDXRB:
    case ARM64_INS_LDXRH:
      gc->exclusive_load_offset = 0;
      break;
    default:
      break;
  }

  ...
}
{% endhighlight %}

在这里，我们可以看到迭代器记录它何时看到独占加载，并跟踪自那以后经过了多少条指令。
这持续最多四条指令——因为这是根据加载、测试、修改和存储值所需的指令数量通过经验测试确定的。
然后这用于防止发出任何并非绝对必要的插桩：

{% highlight c %}
  if ((ec->sink_mask & GUM_EXEC) != 0 &&
      gc->exclusive_load_offset == GUM_INSTRUCTION_OFFSET_NONE)
  {
    gum_exec_block_write_exec_event_code (block, gc,
        GUM_CODE_INTERRUPTIBLE);
  }
{% endhighlight %}

### 耗尽的块

虽然我们在开始之前检查以确保 slab 中为我们当前的插桩块留有最小空间（如果低于此最小值则分配一个新的），
但我们无法预测我们在输入块中可能会遇到多长的指令序列。
确定我们需要多少条输出指令来编写必要的插桩也并不简单
（我们可能有发出不同类型事件、检查排除范围、虚拟化块末尾找到的指令等的代码）。
此外，试图允许插桩代码非顺序是充满困难的。
因此采取的方法是确保每次我们从迭代器读取新指令时，slab 中至少有 1024 字节的空间用于我们的输出。
如果不是这种情况，那么我们将当前地址存储在 `continuation_real_address` 中并返回 `FALSE`，以便迭代器结束。

{% highlight c %}
#define GUM_EXEC_BLOCK_MIN_SIZE 1024

static gboolean
gum_exec_block_is_full (GumExecBlock * block)
{
  guint8 * slab_end = block->slab->data + block->slab->size;

  return slab_end - block->code_end < GUM_EXEC_BLOCK_MIN_SIZE;
}

gboolean
gum_stalker_iterator_next (GumStalkerIterator * self,
                           const cs_insn ** insn)
{
  ...

    if (gum_exec_block_is_full (block))
    {
      gc->continuation_real_address = instruction->end;
      return FALSE;
    }

  ...
}
{% endhighlight %}

我们的调用者 `gum_exec_ctx_obtain_block_for()` 遍历迭代器以生成块，
然后就像有一条分支指令到下一条指令一样行动，本质上终止当前块并开始下一个块。

{% highlight c %}
static GumExecBlock *
gum_exec_ctx_obtain_block_for (GumExecCtx * ctx,
                               gpointer real_address,
                               gpointer * code_address_ptr)
{
  ...

  if (gc.continuation_real_address != NULL)
  {
    GumBranchTarget continue_target = { 0, };

    continue_target.absolute_address = gc.continuation_real_address;
    continue_target.reg = ARM64_REG_INVALID;
    gum_exec_block_write_jmp_transfer_code (block, &continue_target,
        GUM_ENTRYGATE (jmp_continuation), &gc);
  }

  ...
}
{% endhighlight %}

这就像在空间不足的指令之前的输入中遇到了以下指令：

{% highlight asm %}
  B label
label:
{% endhighlight %}

### 系统调用虚拟化

系统调用是从用户模式进入内核模式的入口点。这是应用程序要求内核代表其执行操作的方式，
无论是打开文件还是读取网络套接字。在 AArch64 系统上，这是使用 `SVC` 指令执行的，
而在 Intel 上，指令是 `sysenter`。因此，这里的术语 syscall 和 sysenter 是同义使用的。

系统调用虚拟化由以下例程执行。我们可以看到我们只在 Linux 系统上做任何事情：

{% highlight c %}
static GumVirtualizationRequirements
gum_exec_block_virtualize_sysenter_insn (GumExecBlock * block,
                                         GumGeneratorContext * gc)
{
#ifdef HAVE_LINUX
  return gum_exec_block_virtualize_linux_sysenter (block, gc);
#else
  return GUM_REQUIRE_RELOCATION;
#endif
}
{% endhighlight %}

这是因为 `clone` 系统调用。此系统调用创建一个新进程，该进程与父进程共享执行上下文，
例如文件句柄、虚拟地址空间和信号处理程序。本质上，这有效地创建了一个新线程。
但是当前线程正在被 Stalker 跟踪，而 clone 将创建它的精确副本。
鉴于 Stalker 上下文是基于每个线程的，我们不应该跟踪这个新的子线程。

请注意，对于 AArch64 中的系统调用，前 8 个参数在寄存器 `X0` 到 `X7` 中传递，
系统调用号在 `X8` 中传递，其他参数在堆栈上传递。系统调用的返回值在 `X0` 中返回。
函数 `gum_exec_block_virtualize_linux_sysenter()` 生成处理此类系统调用所需的插桩代码。
我们将看下面的伪代码：

{% highlight c %}
if x8 == __NR_clone:
  x0 = do_original_syscall()
  if x0 == 0:
    goto gc->instruction->begin
  return x0
else:
  return do_original_syscall()
{% endhighlight %}

我们可以看到它首先检查我们是否正在处理 `clone` 系统调用，
否则它只是执行原始系统调用，仅此而已（原始系统调用指令从原始块复制）。
否则，如果是 clone 系统调用，那么我们再次执行原始系统调用。
此时，我们有两个执行线程，系统调用确定每个线程将[返回不同的值](http://man7.org/linux/man-pages/man2/clone.2.html)。
原始线程将接收子线程的 PID 作为其返回值，而子线程将接收值 0。

如果我们收到非零值，我们可以像以前一样继续。我们希望继续跟踪线程并允许执行继续下一条指令。
但是，如果我们收到返回值 0，那么我们就在子线程中。
因此，我们执行到原始块中下一条指令的分支，确保子线程继续运行而没有任何来自 Stalker 的中断。

### 指针认证

最后，我们应该注意，较新版本的 iOS 已经[引入](https://ivrodriguez.com/pointer-authentication-on-armv8-3/)了
[指针认证码](https://events.static.linuxfound.org/sites/events/files/slides/slides_23.pdf)。
指针认证码 (PAC) 利用指针中未使用的位（虚拟地址的高位通常未使用，因为大多数系统最多有 48 位虚拟地址空间）
来存储认证值。这些值是通过使用原始指针、上下文参数（通常是另一个寄存器的内容）和加密密钥计算出来的。
这个想法是密钥不能从用户模式读取或写入，并且如果没有访问权限，生成的指针认证码无法被猜测。

让我们看下面的代码片段：

{% highlight asm %}
pacia lr, sp
stp fp, lr, [sp, #-FRAME_SIZE]!
mov fp, sp

...

ldp fp, lr, [sp], #FRAME_SIZE
autia lr, sp
ret lr
{% endhighlight %}

`pacia` 指令结合 `LR`、`SP` 和密钥的值来生成带有认证码 `LR'` 的 `LR` 版本，并存回 `LR` 寄存器。
此值存储在堆栈中，稍后在函数结束时恢复。`autia` 指令验证 `LR'` 的值。
这是可能的，因为可以剥离 `LR` 高位中的 PAC 以给出原始 `LR` 值，
并且可以像以前一样使用 `SP` 和密钥重新生成指针认证码。结果与 `LR'` 进行检查。
如果值不匹配，则指令生成错误。因此，如果存储在堆栈中的 `LR` 值被修改，
或者堆栈指针本身被破坏，那么验证将失败。这对于防止构建需要将返回地址存储在堆栈中的 ROP 链很有用。
由于 `LR'` 现在存储在堆栈中而不是 `LR`，因此没有密钥就无法伪造有效的返回地址。

Frida 在生成代码时也需要考虑到这一点。当从应用程序使用的寄存器读取指针时
（例如确定间接分支或返回的目的地），有必要在使用之前从地址中剥离这些指针认证码。
这是使用函数 `gum_arm64_writer_put_xpaci_reg()` 实现的。
