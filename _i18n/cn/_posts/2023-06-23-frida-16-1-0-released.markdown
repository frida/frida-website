---
layout: news_item
title: 'Frida 16.1.0 发布'
date: 2023-06-23 23:31:22 +0200
author: oleavr
version: 16.1.0
categories: [release]
---

多年来，我一直梦想着将 Frida 带到用户空间软件之外，以支持检测 OS 内核以及裸机系统。甚至可能是微控制器...

## 微控制器

今年早些时候，我家的猫门坏了。在与零售商反复沟通、仔细检查安装等之后，它会工作一小会儿，然后最终开始出现故障。

这对我们的猫来说显然没什么好玩的：

![cat-door-fail](/img/cat-door-fail.jpg "disappointed cat")

毫不奇怪，它们最终会制造很多噪音，进而使得不得不起来手动让它们进来时很难睡个好觉。

我最终买了第二个猫门，瞧，没有问题了。旧的那个最终积了一段时间的灰尘。我一直在想的是我是否可以调试它，甚至扩展软件以做更多有用的事情。

感到有冲动打开它去戳里面的电子设备，我最终屈服了：

![cat-door-pcb](/img/cat-door-pcb.jpg "cat-door PCB"){: width="100%" }

那看起来像是一个 STM32F030C6T6，这是一个基于 ARM Cortex M0 的 MCU。我的第一个想法是我是否可以转储闪存以进行一些静态分析。

在快速浏览 MCU 文档并进行一点万用表探测后，我弄清楚了 JP12 焊盘：

| PAD 1/2 |           |       | PAD 7/8 |
| :-----: | :-------: | :---: | :-----: |
| BOOT0   | USART1 RX | SWDIO | GND     |
| VDD     | USART1 TX |       | SWCLK   |

这使得拉高 *BOOT0* 变得容易，因此 MCU 启动到其内部引导加载程序而不是用户代码。

通过将 USB 转 3.3V TTL 设备连接到 USART1 焊盘，我可以转储闪存：

{% highlight bash %}
$ ./stm32flash -r firmware.bin /dev/ttyUSB0
stm32flash 0.7

http://stm32flash.sourceforge.net/

Interface serial_posix: 57600 8E1
Version      : 0x31
Option 1     : 0x00
Option 2     : 0x00
Device ID    : 0x0444 (STM32F03xx4/6)
- RAM        : Up to 4KiB  (2048b reserved by bootloader)
- Flash      : Up to 32KiB (size first sector: 4x1024)
- Option bytes  : 16b
- System memory : 3KiB
Memory read
Read address 0x08008000 (100.00%) Done.
{% endhighlight %}

并执行一些静态分析：
![cat-door-firmware](/img/cat-door-firmware.png "cat-door firmware")

鉴于另外两个焊盘连接到 SWDIO 和 SWCLK，用于串行线调试 (SWD)，自然的下一步是将 [Raspberry Pi Debug Probe][] 连接到这些焊盘。设置好之后，我启动了 [OpenOCD][]：

{% highlight bash %}
$ openocd -f interface/cmsis-dap.cfg -f target/stm32f0x.cfg
Open On-Chip Debugger 0.11.0-g8e3c38f7-dirty (2023-05-05-14:25)
Licensed under GNU GPL v2
For bug reports, read
	http://openocd.org/doc/doxygen/bugs.html
Info : auto-selecting first available session transport "swd". To override use 'transport select <transport>'.
Info : Listening on port 6666 for tcl connections
Info : Listening on port 4444 for telnet connections
Info : Using CMSIS-DAPv2 interface with VID:PID=0x2e8a:0x000c, serial=E6614103E78B482F
Info : CMSIS-DAP: SWD  Supported
Info : CMSIS-DAP: FW Version = 2.0.0
Info : CMSIS-DAP: Interface Initialised (SWD)
Info : SWCLK/TCK = 0 SWDIO/TMS = 0 TDI = 0 TDO = 0 nTRST = 0 nRESET = 0
Info : CMSIS-DAP: Interface ready
Info : clock speed 1000 kHz
Info : SWD DPIDR 0x0bb11477
Info : stm32f0x.cpu: hardware has 4 breakpoints, 2 watchpoints
Info : starting gdb server for stm32f0x.cpu on 3333
Info : Listening on port 3333 for gdb connections
{% endhighlight %}

我一直在思考的一个想法是添加一个新的 Frida 后端，您只能附加到 PID 0。在那里加载的任何脚本实际上都将在本地运行，并实现熟悉的 [JavaScript API][]。任何访问内存的 API，例如通过执行 *ptr('0x80000').readInt()* 取消引用 *int \** 时，最终都会查询目标，在上述情况下通过 SWD。

我最初开始草拟这个，后端将通过其 telnet 接口与 OpenOCD 守护进程对话。但我很快意识到与它的 GDB 兼容远程存根对话会更好。通过这种方式，Frida 将能够检测任何具有可用远程存根的目标。无论是 OpenOCD, [Corellium][] (iOS 内核检测!), QEMU 等。

至于 Interceptor，我的想法是基本功能将使用断点实现。但是，仅当用户提供 JavaScript 回调时。如果提供函数指针，我们可以执行内联 hook，以便目标可以在没有任何陷阱/与主机乒乓的情况下运行。这意味着它甚至可以用于观察和修改 OS 内核或 MCU 固件内的热代码。

经过一些初步草图，我能够运行以下脚本：

{% highlight js %}
Interceptor.breakpointKind = 'hard';

const THUMB_BIT = 1;

const initRest = ptr('0x0800306a').or(THUMB_BIT);
Interceptor.attach(initRest, {
  onEnter(args) {
    console.log('>>> init_rest()',
        JSON.stringify(this.context, null, 2));
  },
  onLeave(retval) {
    console.log(`<<< init_rest() retval=${retval}`);
  }
});
{% endhighlight %}

使用 Frida REPL：

{% highlight bash %}
$ frida -D barebone -p 0 -l demo.js
     ____
    / _  |   Frida 16.1.0 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://frida.re/docs/home/
   . . . .
   . . . .   Connected to GDB Remote Stub (id=barebone)

[Remote::SystemSession ]-> $gdb.continue()
[Remote::SystemSession ]-> >>> init_rest() {
  "r7": "0xffffffff",
  "pc": "0x800306a",
  "r8": "0xffffffff",
  "xPSR": "0x41000000",
  "r9": "0xffffffff",
  "sp": "0x20000578",
  "r0": "0x0",
  "r10": "0xffffffff",
  "lr": "0x8003069",
  "r1": "0x40021008",
  "r11": "0xffffffff",
  "r2": "0xffffffff",
  "r12": "0xffffffff",
  "r3": "0xffffffff",
  "r4": "0xffffffff",
  "r5": "0xffffffff",
  "r6": "0xffffffff"
}
<<< init_rest() retval=0x1
{% endhighlight %}

这里有几点需要注意：

- 我们将 *Interceptor.breakpointKind* 设置为 *hard*，因为我们的目标代码驻留在闪存中，这意味着软件断点将不起作用。如果我使用的是 [J-Link][] 或类似的 SWD 接口，这将是不必要的，因为添加软件断点时它会透明地重新刷新。
- 后端尚未自动恢复，因此我们通过 *$gdb.continue()* 手动执行此操作，这是 [this internal API][] 的一部分，它向 JavaScript 公开了大部分 [GDB.Client][]。这旨在成为内部实现细节，但在新后端成熟时将需要它——它还不应被视为稳定的 API。
- 我们设置最低有效位以向 Interceptor 指示目标函数使用 Thumb 指令编码。如果您以前在 32 位 ARM 上使用过 Frida 的常规后端，这部分可能已经很熟悉了。
- 新的 Barebone 后端默认连接到 *127.0.0.1:3333* 处的 GDB 兼容远程存根。这与 OpenOCD 通常默认的情况相匹配，但可以通过设置 *FRIDA_BAREBONE_ADDRESS* 环境变量来覆盖。

## OS 内核

虽然我有趣的小猫门支线任务是该频谱微小部分的绝佳测试用例，但在支持更大的系统方面也有很大的潜力。

其中一个更酷的用例肯定是 Corellium，因为这意味着我们可以检测 iOS 内核。使用 [Tamarin Cable][]，甚至应该可以在 checkm8 可利用的物理设备上使其工作。

不过在我们触及那个之前，让我们看看我们是否可以让 QEMU 和实时 Linux 内核一起运行。

### Linux

首先，我们将启动一个我们可以玩的 VM：

{% highlight bash %}
$ pip install arm_now
$ arm_now start aarch64 --add-qemu-options='-gdb tcp::9000'
...
Welcome to arm_now
buildroot login:
{% endhighlight %}

接下来，我们将使用 Frida REPL 环顾四周：

{% highlight bash %}
$ export FRIDA_BAREBONE_ADDRESS=127.0.0.1:9000
$ frida -D barebone -p 0
     ____
    / _  |   Frida 16.1.0 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://frida.re/docs/home/
   . . . .
   . . . .   Connected to GDB Remote Stub (id=barebone)

[Remote::SystemSession ]-> Process.arch
"arm64"
[Remote::SystemSession ]-> Process.enumerateRanges('r-x')
[
    {
        "base": "0xffffff8008080000",
        "protection": "r-x",
        "size": 4259840
    }
]
[Remote::SystemSession ]-> $gdb.state
"stopped"
[Remote::SystemSession ]-> $gdb.exception
{
    "breakpoint": null,
    "signum": 2,
    "thread": {}
}
[Remote::SystemSession ]-> $gdb.exception.thread.readRegisters()
{
    "cpsr": 1610613189,
    "pc": "0xffffff8008096648",
    "sp": "0xffffff80085f3f10",
    "x0": "0x0",
    "x1": "0xffffff80085e6b78",
    "x10": "0x880",
    "x11": "0xffffffc00e877180",
    "x12": "0x0",
    "x13": "0xffffffc00ffe1f30",
    "x14": "0x0",
    "x15": "0xfffffff8",
    "x16": "0xffffffbeff000000",
    "x17": "0x0",
    "x18": "0xffffffc00ffe17e0",
    "x19": "0xffffff80085e0000",
    "x2": "0x40079f5000",
    "x20": "0xffffff80085f892c",
    "x21": "0xffffff80085f88a0",
    "x22": "0xffffff80085ffe80",
    "x23": "0xffffff80085ffe80",
    "x24": "0xffffff80085d5028",
    "x25": "0x0",
    "x26": "0x0",
    "x27": "0x0",
    "x28": "0x405a0018",
    "x29": "0xffffff80085f3f10",
    "x3": "0x30c",
    "x30": "0xffffff800808492c",
    "x4": "0x0",
    "x5": "0x40079f5000",
    "x6": "0x1",
    "x7": "0x1c0",
    "x8": "0x2",
    "x9": "0xffffff80085f3e80"
}
[Remote::SystemSession ]->
{% endhighlight %}

您可能想知道我们是如何实现 *Process.enumerateRanges()* 的。这部分目前仅在 arm64 上实现，它是通过 [parsing the page tables][] 完成的。（如果我们正在与 Corellium 的远程存根对话，我们使用特定于供应商的监视器命令来节省大量网络往返。）

所以现在我们正在窥视正在运行的内核，我们可能想做的一件事是查找内部函数和数据结构。这就是内存扫描 API 派上用场的地方：

{% highlight js %}
for (const r of Process.enumerateRanges('r-x')) {
  console.log(JSON.stringify(r, null, 2));
  const matches = Memory.scanSync(r.base, r.size,
      '7b2000f0 fa03082a 992480d2 : 1f00009f ffffffff 1f00e0ff');
  console.log('Matches:', JSON.stringify(matches, null, 2));
}
{% endhighlight %}

在这里，我们正在寻找 Linux 内核的 [arm64 syscall handler][]，匹配其前三条指令。我们使用掩码功能来掩盖 ADRP 和 MOV 指令（第一条和第三条指令）的立即数。

让我们试一试：

{% highlight bash %}
$ frida -D barebone -p 0 -l scan.js
     ____
    / _  |   Frida 16.1.0 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://frida.re/docs/home/
   . . . .
   . . . .   Connected to GDB Remote Stub (id=barebone)
Attaching...
{
  "base": "0xffffff8008080000",
  "size": 4259840,
  "protection": "r-x"
}
Matches: [
  {
    "address": "0xffffff8008082f00",
    "size": 12
  }
]
[Remote::SystemSession ]->
{% endhighlight %}

所以现在我们已经动态插桩到了内核的内部系统调用处理程序！🚀

重新实现内存扫描功能对我个人来说是亮点之一，因为 [@hsorbo][] 和我在结对编程中玩得很开心。该实现从概念上讲与我们在 jailed iOS 的 Fruity 后端和新的 Linux 注入器中所做的非常相似：我们可以只传输搜索算法在目标上运行，而不是将数据传输到主机并搜索它。

[memory scanner implementation][] 是用 Rust 编写的，并帮助为我将在本文稍后介绍的一个很酷的新功能奠定了基础。

所以，既然我们知道 Linux 内核的系统调用处理程序在哪里，我们可以使用 Interceptor 安装指令级 hook：

{% highlight js %}
const el0Svc = ptr('0xffffff8008082f00');
Interceptor.attach(el0Svc, function (args) {
  const { context } = this;
  const scno = context.x8.toUInt32();
  console.log(`syscall! scno=${scno}`);
});
{% endhighlight %}

并在我们正在运行的 VM 上尝试一下：

{% highlight bash %}
$ frida -D barebone -p 0 -l kernhook.js
     ____
    / _  |   Frida 16.1.0 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://frida.re/docs/home/
   . . . .
   . . . .   Connected to GDB Remote Stub (id=barebone)

[Remote::SystemSession ]-> $gdb.continue()
[Remote::SystemSession ]-> syscall! scno=63
syscall! scno=64
syscall! scno=73
syscall! scno=63
syscall! scno=64
syscall! scno=73
syscall! scno=63
syscall! scno=64
syscall! scno=56
syscall! scno=62
syscall! scno=64
syscall! scno=57
syscall! scno=29
syscall! scno=134
...
{% endhighlight %}

就是这样——我们正在监控整个系统的系统调用！💥

### Rust

如果您尝试前面的示例，您可能会注意到的第一件事是我们大大减慢了系统的速度。这是因为当指定 JavaScript 函数作为回调时，Interceptor 使用断点。

不过不用担心。如果我们用机器码编写回调并传递 NativePointer，Interceptor 将选择不同的策略：它将修改目标的机器码以将执行重定向到蹦床，蹦床反过来调用我们指定地址的函数。

太好了。我们只需要将我们的机器码放入内存。你们中的一些人可能熟悉我们的 [CModule API][]。我们还没有在这个新的 Barebone 后端实现那个（我们最终会实现的！），但我们有更好的东西。输入 *RustModule*：

{% highlight js %}
const kernBase = ptr('0xffffff8008080000');
const procPidStatus = kernBase.add(0x15e600);

const m = new RustModule(`
#[no_mangle]
pub unsafe extern "C" fn hook(ic: &mut gum::InvocationContext) -> () {
    let regs = &mut ic.cpu_context;
    println!("proc_pid_status() was called with x0={:#x} x1={:#x}",
        regs.x[0],
        regs.x[1],
    );
}
`);

Interceptor.attach(procPidStatus, m.hook);
{% endhighlight %}

RustModule 实现使用本地 Rust 工具链（假定在您的 PATH 上），将您提供的代码编译为 *no_std* 自包含 ELF。它重新定位此 ELF 并将其写入目标的内存。作为此过程的一部分，它还将解析 MMU 的页表并在那里插入新条目，以便上传的代码成为虚拟地址空间的一部分，其中页面是读/写/执行的。

在这个例子中，我们在我们的实时 Linux 内核中 hook [proc_pid_status()][]。

请注意，可以使用 *File.readAllText()* 来避免在 JavaScript 中内联 Rust 代码。为了简洁起见，我们在这里使用内联代码。

现在，有了我们 Rust 驱动的代理，让我们试一试：

{% highlight bash %}
$ frida -D barebone -p 0 -l kernhook2.js
     ____
    / _  |   Frida 16.1.0 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://frida.re/docs/home/
   . . . .
   . . . .   Connected to GDB Remote Stub (id=barebone)

Error: to enable this feature, set FRIDA_BAREBONE_HEAP_BASE to the physical base address to use, e.g. 0x48000000
    at <eval> (/home/oleavr/src/demo/kernhook2.js:13)
    at evaluate (native)
    at <anonymous> (/frida/repl-2.js:1)

[Remote::SystemSession ]->
{% endhighlight %}

哎呀！那不太行。我们的新后端仍然缺少一块：我们还没有任何“内核桥”到位，可以自动指纹识别已知内核的内部结构，以便找到我们可以使用的合适的内部内存分配器。这也将需要实现诸如 *Process.enumerateModules()* 之类的 API，这将允许列出加载的内核模块/kext。我们还可以定位内核的进程列表并实现 *enumerate_processes()*，以便 frida-ps 工作。这些只是几个例子... 将 frida-gadget 注入用户空间进程怎么样？对于我们想要避免修改闪存的嵌入式系统来说，这将非常有用。无论如何，我离题了 😊

因此，在 MCU 和未知内核上，如果您想使用 RustModule、内联 hook 模式下的 Interceptor、Memory.alloc() 等侵入性功能，您必须告诉 Frida 我们可能会破坏物理内存中的哪个位置。

考虑到这一点，让我们重试我们的示例，但这次我们将设置 *FRIDA_BAREBONE_HEAP_BASE* 环境变量：

{% highlight bash %}
$ export FRIDA_BAREBONE_HEAP_BASE=0x48000000
$ frida -D barebone -p 0 -l kernhook2.js
     ____
    / _  |   Frida 16.1.0 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://frida.re/docs/home/
   . . . .
   . . . .   Connected to GDB Remote Stub (id=barebone)

[Remote::SystemSession ]-> m
{
    "hook": "0xffffff80080103e0"
}
[Remote::SystemSession ]-> $gdb.continue()
{% endhighlight %}

耶！🎉 所以现在，在我们运行 QEMU 的终端中，让我们尝试访问 */proc/$pid/status* 三次，以便调用 hook 函数：

{% highlight bash %}
# head -3 /proc/self/status
Name:	head
Umask:	0022
State:	R (running)
# head -3 /proc/self/status
Name:	head
Umask:	0022
State:	R (running)
# head -3 /proc/self/status
Name:	head
Umask:	0022
State:	R (running)
{% endhighlight %}

在我们的 REPL 中，我们应该看到我们的 *hook()* 被击中三次：

{% highlight bash %}
proc_pid_status() was called with x0=0xffffffc00d4bca00 x1=0xffffff8008608758
proc_pid_status() was called with x0=0xffffffc00d4bc780 x1=0xffffff8008608758
proc_pid_status() was called with x0=0xffffffc00d4bc780 x1=0xffffff8008608758
{% endhighlight %}

它有效！🥳

不过有一点很重要：在我们的示例中，我们使用了 *println!()*, 这实际上会导致目标击中断点，以便主机可以读出传递给它的消息，并像 JavaScript 中的 *console.log()* 一样将其冒泡。这意味着您应该只将此功能用于临时调试目的，如果在热代码路径上，请限制其调用频率。

您可能想做的下一件事是将外部符号传递到您的 RustModule 中。例如，如果您想从 Rust 代码调用内部内核函数。这是通过像这样声明它们来实现的：

{% highlight rs %}
extern "C" {
    fn frobnicate(data: *const u8, len: usize);
}
{% endhighlight %}

然后在构造 RustModule 时，通过第二个参数将其传入：

{% highlight js %}
const m = new RustModule(source, {
  frobnicate: ptr('0xffffff8008084320'),
});
{% endhighlight %}

对于熟悉我们 CModule API 的人来说，这部分完全相同。您还可以使用 NativeCallback 在主机端（JavaScript 中）实现部分，但这需要小心处理以避免性能瓶颈。反方向也有 NativeFunction，您可以使用它从 JavaScript 调用 Rust 代码。

最后但并非最不重要的一点是，您可能还想从 [crates.io][] 导入现有的 Rust crate。这也受支持：

{% highlight js %}
const m = new RustModule(source, {}, {
  dependencies: [
    'cstr_core = { version = "0.2.6", default-features = false }',
  ]
});
{% endhighlight %}

## Corellium

令人兴奋的是，上述所有 Linux 位在 Corellium 上也“正常工作”。您所要做的就是将 *FRIDA_BAREBONE_ADDRESS* 指向 Corellium UI 中“Advanced Options” -> “gdb”下显示的端点。

感谢 Corellium 的优秀人员在做这件事时的支持。他们甚至实现了新的协议功能以提高互操作性 🔥

## 未来

这个新后端目前应被视为 alpha 质量，但我认为它已经能够做很多有用的事情，把它放在分支上太可惜了。

您可能会注意到实现的 JS API 仅涵盖子集，并且并非所有功能都在非 arm64 目标上可用。但随着后端的成熟，所有这些都会得到改善。（非常欢迎 Pull-request！）

作为一个有趣的旁注，这是附加到 BeOS 内核的 Frida：

![beos-kernel](/img/barebone-beos.png "BeOS kernel"){: width="100%" }

## EOF

还有很多其他令人兴奋的更改，所以一定要查看下面的变更日志。

享受吧！

### 变更日志

- 添加 Barebone 后端。（上面已广泛介绍。）
- objc: 处理修饰符。这使得类型解析更可靠，尤其是在处理通常具有“atomic”修饰符的 ivar 时：由于修饰符最终被视为未知类型而引发异常。感谢 [@mrmacete][]！
- android: 修复对 Android 14 的支持。感谢 [@gsingh93][]！也感谢 [@jayluxferro][] 为我在合并 [@gsingh93][] 的 PR 时犯的错误贡献了后续修复。
- gum-graft: 添加对链式导入的支持。感谢 [@mrmacete][]！
- gumjs: 添加 NativePointer#readVolatile()，提供一种安全的方式来读取可能在中途取消映射或更改其内存保护的内存。感谢 [@hsorbo][]！
- darwin: 改进 tvOS 支持以涵盖 frida-server。感谢 [@tmm1][]！
- darwin: 堵塞回退 kill() 逻辑中的内存泄漏。感谢 [@tmm1][]！
- fruity: 处理获取 dyld 符号失败。
- compiler: 将 frida-compile 升级到 16.2.2。依赖项的源映射现在也已捆绑——感谢 [@vfsfitvnm][]！
- compiler: 将 @types/frida-gum 升级到 18.3.2，现在具有改进的 *hexdump()* 类型定义。
- gdb: 添加 GDB.Client，通过剔除 Fruity 的 LLDB.Client 的核心，并在其之上添加许多协议增强和互操作性修复。
- elf-module: 改进 API 并使其跨平台。支持从 blob 加载，公开重定位，并提高整体稳健性。
- capstone: 修复使用 MSVC 构建时 x86 上的崩溃。


[Raspberry Pi Debug Probe]: https://www.raspberrypi.com/products/debug-probe/
[OpenOCD]: https://openocd.org/
[JavaScript API]: /docs/javascript-api/
[Corellium]: https://www.corellium.com/
[J-Link]: https://www.segger.com/products/debug-probes/j-link/technology/flash-breakpoints/
[this internal API]: https://github.com/frida/frida-core/blob/0c6737becb603871f62c775f06214b27c3e208ad/src/barebone/script.vala#L220-L257
[GDB.Client]: https://github.com/frida/frida-core/blob/0c6737becb603871f62c775f06214b27c3e208ad/src/gdb.vala#L3
[Tamarin Cable]: https://github.com/stacksmashing/tamarin-firmware
[parsing the page tables]: https://github.com/frida/frida-core/blob/0c6737becb603871f62c775f06214b27c3e208ad/src/barebone/arch-arm64/machine.vala#L38-L91
[arm64 syscall handler]: https://github.com/torvalds/linux/blob/569dbb88e80deb68974ef6fdd6a13edb9d686261/arch/arm64/kernel/entry.S#L800-L802
[@hsorbo]: https://twitter.com/hsorbo
[memory scanner implementation]: https://github.com/frida/frida-core/tree/0c6737becb603871f62c775f06214b27c3e208ad/src/barebone/helpers
[CModule API]: /docs/javascript-api/#cmodule
[proc_pid_status()]: https://github.com/torvalds/linux/blob/569dbb88e80deb68974ef6fdd6a13edb9d686261/fs/proc/array.c#L372-L391
[crates.io]: https://crates.io/
[@mrmacete]: https://twitter.com/bezjaje
[@gsingh93]: https://github.com/gsingh93
[@jayluxferro]: https://github.com/jayluxferro
[@tmm1]: https://twitter.com/tmm1
[@vfsfitvnm]: https://github.com/vfsfitvnm
