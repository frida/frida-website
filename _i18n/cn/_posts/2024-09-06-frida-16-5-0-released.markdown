---
layout: news_item
title: 'Frida 16.5.0 发布'
date: 2024-09-06 21:57:17 +0200
author: oleavr
version: 16.5.0
categories: [release]
---

你们中的一些人可能遇到过这样的情况：内存中的一段数据看起来很有趣，你想找到负责它的代码。你可能尝试过 Frida 的 MemoryAccessMonitor API，但发现页面粒度很难处理。也就是说，你可能不得不收集许多样本，直到你幸运地捕获到访问该页面上特定字节的代码。这在具有 4K 页面的系统上可能已经够难了，在具有 16K 页面的现代 Apple 系统上甚至更糟。

为了解决这个问题，[@hsorbo][] 和我倒满咖啡开始工作，实现了对硬件断点和观察点的支持。长话短说，Process.enumerateThreads() 返回的线程对象现在具有 setHardwareBreakpoint()、setHardwareWatchpoint() 以及稍后取消设置它们的相应方法。然后将这些与 Process.setExceptionHandler() 结合使用，在其中调用取消设置方法并返回 true 以表示异常已处理，应恢复执行。

## 演示时间

让我们试用一下这些新 API。作为目标，我们将选择 id Software 全新的 2024 年重新发布的 DOOM + DOOM II。

![DOOM](/img/doom-e1m1.jpg "DOOM E1M1")

我们可能想做的第一件事是弄清楚子弹数量存储在内存中的位置。让我们编写一个微型代理来帮助我们实现这一目标：

{% highlight js %}
let matches = [];

function scan(pattern) {
  const locations = new Set();
  for (const r of Process.enumerateMallocRanges()) {
    for (const match of Memory.scanSync(r.base, r.size, pattern)) {
      locations.add(match.address.toString());
    }
  }
  matches = Array.from(locations).map(ptr);
  console.log('Found', matches.length, 'matches');
}

function reduce(val) {
  matches = matches.filter(location => location.readU32() === val);
  console.log('Filtered down to:');
  console.log(JSON.stringify(matches));
}

function patternFromU32(val) {
  return new MatchPattern(ptr(val).toMatchPattern().substr(0, 11));
}
{% endhighlight %}

并将其加载到游戏中：

{% highlight sh %}
$ frida -n doom.exe -l demo.js
…
[Local::doom.exe ]->
{% endhighlight %}

我们知道目前有 50 发子弹，所以让我们找到所有包含值 50 的堆分配，编码为本机 uint32：

{% highlight sh %}
[Local::doom.exe ]-> scan(patternFromU32(50))
Found 6947 matches
{% endhighlight %}

这相当多。让我们通过发射一颗子弹来缩小范围，并检查这些位置中哪些现在包含值 49：

{% highlight sh %}
[Local::doom.exe ]-> reduce(49)
Filtered down to:
["0x1fbf5191884"]
{% endhighlight %}

宾果！既然我们知道子弹数量存储在内存中的位置，我们的下一步是找到发射子弹时更新子弹数量的代码。让我们向代理添加另一个辅助函数：

{% highlight js %}
function installWatchpoint(address, size, conditions) {
  const thread = Process.enumerateThreads()[0];

  Process.setExceptionHandler(e => {
    console.log(`\n=== Handler got ${e.type} exception at ${e.context.pc}`);

    if (Process.getCurrentThreadId() === thread.id &&
        ['breakpoint', 'single-step'].includes(e.type)) {
      thread.unsetHardwareWatchpoint(0);
      console.log('\tDisabled hardware watchpoint');
      return true;
    }

    console.log('\tPassing to application');
    return false;
  });

  thread.setHardwareWatchpoint(0, address, size, conditions);

  console.log('Ready');
}
{% endhighlight %}

并调用它：

{% highlight sh %}
[Local::doom.exe ]-> installWatchpoint(ptr('0x1fbf5191884'), 4, 'w')
Ready
{% endhighlight %}

接下来我们将切换回游戏并再发射一颗子弹：

{% highlight sh %}
[Local::doom.exe ]->
=== Handler got system exception at 0x7ffc2bc2fabc
        Passing to application

=== Handler got single-step exception at 0x7ff6f0a21010
        Disabled hardware watchpoint
{% endhighlight %}

耶，看起来很有希望。让我们对该地址进行符号化：

{% highlight sh %}
[Local::doom.exe ]-> ammoCode = ptr('0x7ff6f0a21010')
"0x7ff6f0a21010"
[Local::doom.exe ]-> ammoModule = Process.getModuleByAddress(ammoCode)
{
    "base": "0x7ff6f0730000",
    "name": "DOOM.exe",
    "path": "C:\\Program Files (x86)\\Steam\\steamapps\\common\\Ultimate Doom\\rerelease\\DOOM.exe",
    "size": 15495168
}
[Local::doom.exe ]-> offset = ammoCode.sub(ammoModule.base)
"0x2f1010"
{% endhighlight %}

让我们使用 r2 仔细看看：

![DOOM](/img/doom-r2.png "DOOM static analysis")

我们可以看到，我们在异常处理程序中观察到的程序计数器位于触发我们观察点的 `sub` 之后的指令上。

所以从这里我们可以设置一个内联 hook，只要发射子弹就会触发：

{% highlight js %}
Interceptor.attach(Module.getBaseAddress('doom.exe').add(0x2f1010), function () {
  const ammoLeft = this.context.rax.add(4).readU32();
  console.log(`Shots fired! Ammo left: ${ammoLeft}`);
});
{% endhighlight %}

{% highlight sh %}
[Local::doom.exe ]-> Shots fired! Ammo left: 42
Shots fired! Ammo left: 41
Shots fired! Ammo left: 40
Shots fired! Ammo left: 39
Shots fired! Ammo left: 38
{% endhighlight %}

我们可以同样轻松地为自己制作一个无限弹药作弊：

{% highlight js %}
Interceptor.attach(Module.getBaseAddress('doom.exe').add(0x2f100d), function () {
  this.context.rbx = ptr(0);
  console.log(`Shots fired! Pretending no ammo was actually used`);
});
{% endhighlight %}

{% highlight sh %}
[Local::doom.exe ]-> Shots fired! Pretending no ammo was actually used
Shots fired! Pretending no ammo was actually used
Shots fired! Pretending no ammo was actually used
Shots fired! Pretending no ammo was actually used
Shots fired! Pretending no ammo was actually used
{% endhighlight %}

看妈，无限弹药！

请注意，我们也可以通过使用 Memory.patchCode() 将 `sub` 替换为 3 字节的 `nop` 来实现这一点，X86Writer 可以通过 putNopPadding(3) 为我们做到这一点。Interceptor hook 的优点是当我们的脚本卸载时会自动回滚，并且很容易执行任意代码。

## Windows on ARM

此版本的另一个亮点是我们现在支持 Windows on ARM。这意味着 arm64 版本的 Frida 可以注入本机 arm64 进程，以及模拟的 x86_64 和 x86 进程。

但是我们还没有提供二进制文件，因为我们在等待 GitHub 向 OSS 项目提供 arm64 运行器，目前仅限于他们的团队和企业云客户。虽然从 x86_64 构建机器交叉编译在技术上是可行的，但我们决定推迟这一点，因为我们很快遇到了 Meson 的 MSVC 支持问题。

## EOF

还有大量其他令人兴奋的更改，所以一定要查看下面的变更日志。

享受吧！

## 变更日志

- thread: 支持硬件断点和观察点。
- fruity: 修复 perform_on_lwip_thread() 中的死锁。
- windows: 添加对 arm64 的支持。
- windows: 将 Exceptor 迁移到 Microsoft 的 VEH API。
- linux: 处理分离时进程消失的情况。感谢 [@ajwerner][]！
- linux: 修复 MIPS 上的 clone() 包装器。
- java: 处理未导出的 Android GC 循环处理程序。感谢 [@thinhbuzz][]！
- java: 添加对 Windows 上 OpenJDK 17 的初步支持。感谢 [@FrankSpierings][]！
- meson: 将 frida-netif 添加到公共 frida-core，以便 frida-core devkits 包含所有需要的符号。
- node: 添加 Cancellable.withTimeout() 便利工厂函数。感谢 [@hsorbo][]！
- node: 添加 Cancellable.combine() 便利方法。感谢 [@hsorbo][]！


[@hsorbo]: https://twitter.com/hsorbo
[@ajwerner]: https://github.com/ajwerner
[@thinhbuzz]: https://github.com/thinhbuzz
[@FrankSpierings]: https://github.com/FrankSpierings
