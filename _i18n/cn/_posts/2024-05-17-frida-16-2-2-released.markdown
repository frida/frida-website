---
layout: news_item
title: 'Frida 16.2.2 发布'
date: 2024-05-17 18:26:11 +0200
author: oleavr
version: 16.2.2
categories: [release]
---

现在是发布时间，这个版本充满了改进！🎉

## 构建系统

在对我们的构建系统状况不满意多年之后，我终于鼓起勇气重组它——以一种大的方式。

### 用户体验

困扰我的一件事是，我们的构建系统感觉非常古怪和复杂。你会调用 *make* 并看到你可以构建的东西的菜单。但是该菜单会根据你运行它的操作系统而有所不同。更改构建选项意味着编辑 config.mk 或在命令行上覆盖它们。如果你在 Windows 上，你必须使用 Visual Studio (MSVS)。

MSVS 构建系统现在已经消失了，你可以像构建许多其他 OSS 项目一样构建 Frida：

{% highlight bash %}
$ ./configure
$ make
{% endhighlight %}

如果你不需要传递任何选项（例如 --prefix），则可以跳过 *configure* 步骤。这个脚本实际上只是 Meson setup 命令的一个薄包装器，你可以通过添加 `--` 后跟选项将选项直接传递给 Meson。你也可以运行 *make install* 来安装东西，它支持 DESTDIR 环境变量来更改输出的位置。

交叉编译也很容易；例如，如果你想为 iOS/arm64 构建，请使用 --host=ios-arm64 调用 configure。如果你有嵌入式系统的工具链，请传递 --host=$triplet，它将在你的 PATH 上查找 $triplet-gcc, $triplet-g++ 等。你还可以将 CFLAGS, LDFLAGS 等添加到环境中以传递额外的标志，就像你期望从其他构建系统那样。

很酷的是，我们不同的 repo 现在可以独立构建。你可以克隆 frida-gum repo 并构建它，就像你可以对 frida-python, frida-tools 等做的那样。frida repo 不再那么重要，它只是为了能够对一组 repo 进行版本控制，并托管用于滚动新版本的 CI。

每个 repo 包含任何需要的 subprojects/*.wrap 文件，告诉 Meson 在哪里可以找到依赖项。这意味着如果你获取 frida-core 并尝试构建它，而你的 PKG_CONFIG_PATH 上还没有 frida-gum，它会自动为你获取并构建它。同样整洁的是，我们的 Python 和 Node.js 绑定现在利用这一点从源代码构建，如果找不到或无法下载 .whl 或预构建。

所以现在我们不同的组件作为子项目运行良好，这也意味着任何人都可以同样轻松地将 Frida 组件集成到他们自己的项目中。你所要做的就是在项目顶级源目录中的 subprojects/ 添加一个 .wrap-file，并从你的 meson.build 调用 dependency()。Meson 然后首先在你的系统上查找，如果找不到依赖项，它将克隆 subprojects/ 中的 git repo 并将其作为项目的一部分进行构建。也可以告诉 Meson 强制这种回退而不查看你的系统。

这是 Gum 的 .wrap-file 可能的样子：

{% highlight ini %}
[wrap-git]
url = https://github.com/frida/frida-gum.git
revision = 16.2.4
depth = 1

[provide]
dependency_names = frida-gum-1.0, frida-gum-heap-1.0, frida-gum-prof-1.0, frida-gumjs-1.0, frida-gumjs-inspector-1.0
{% endhighlight %}

对于 frida-core：

{% highlight ini %}
[wrap-git]
url = https://github.com/frida/frida-core.git
revision = 16.2.4
depth = 1

[provide]
dependency_names = frida-core-1.0
{% endhighlight %}

我们的薄 Meson 包装器也很容易上手，你可以在 [here][] 阅读更多相关信息。

### 一点历史

我选择为 Windows 维护单独的构建系统的原因是，我以前与相当多经验丰富的 Windows 开发人员合作过，并注意到如果他们可以使用自己喜欢的 IDE 进行工作，他们会对 OSS 项目更感兴趣。对他们来说重要的是，他们可以在调试器中查看崩溃，跳转到属于 OSS 库的帧，并能够添加一些临时日志代码。然后按“运行”热键让 IDE 增量编译并重新链接所有内容，以获得简短而甜蜜的反馈循环。

当时，Frida 的非 Windows 构建系统是 autotools。我们后来搬到了 Meson。虽然 Meson 有一个 MSVS 后端，这意味着我们可以让它为我们生成 MSVS 项目文件，但有一个问题阻止了我们这样做。与 MSVS 不同，你可以在同一个“解决方案”（工作区）中混合针对不同机器的项目，Meson 一次只支持为一台机器编译，除了构建机器。由于 Frida 支持将代码注入例如 Windows 上的 32 位和 64 位目标，如果我们删除 MSVS 构建系统，我们将引入可用性回归。所以因为这个我犹豫要不要放弃 MSVS 构建系统。

我们在非 Windows 上也遇到了同样的挑战。我最终通过编写一个 Makefile 来解决它，该 Makefile 为每个架构调用 Meson，将它们粘合在一起。虽然这确实有效，但我从未让它达到增量构建也能可靠工作的程度。然而，今年 3 月下旬，我终于确定了一种在 frida-core 中本地解决此问题的方法——这是我们需要这种多架构疯狂的唯一组件。通过从 custom_target() 递归调用 Meson，我们可以为其他架构构建所需的组件。

这花了很多工作才使其正常工作，但一旦到了那里，它让堆栈其余部分的工作变得更加愉快。*frida* repo 的 Makefile 和 shell 脚本可以被删除并替换为 Meson。CI 变得更简单、更统一。任何人都可以克隆 frida-core repo 并运行 *make*，生成的二进制文件将支持跨架构。（除非通过 --disable-compat / -Dfrida-core:compat=disabled 显式禁用。）

现在你可能想知道为什么我们还在运行 *make*，如果我们现在只使用 Meson。我最终在 Meson 周围编写了一个薄包装器，它可以自动下载预构建的依赖项，为较小的二进制文件选择合理的链接器标志等。每个 repo 中的新 *configure* 和 *Makefile* 文件负责调用 releng/meson_configure.py 和 releng/meson_make.py，它们构成了 Meson 周围的薄包装器。*releng* 目录是一个子模块，由 Frida 的 repo 共享。在调用包装器之前做的另一件事是确保 releng 子模块已被初始化和更新。

### 维护

在此版本之前，我们维护着七个不同的构建系统：

1. Meson (主要组件，在非 Windows 上)
2. Visual Studio (主要组件，在 Windows 上)
3. GNU Make (主要组件元构建系统，在非 Windows 上)
4. setuptools (Python 绑定)
5. GYP (Node.js 绑定)
6. Xcode (Swift 绑定)
7. QMake (QML 绑定)

截至此版本，我很高兴地宣布我们只剩下一个构建系统：Meson。

以前情况的主要痛点是必须同时处理 1) 和 2)，因为它们涉及所有主要组件。这意味着像添加源文件这样简单的事情需要了解两个不同的构建系统。不仅如此，例如 Linux 上的贡献者通常很难测试他们的 Visual Studio 构建系统更改。

另一个方面是，如果像添加新文件这样简单的事情涉及处理两个构建系统，开发人员就不太愿意重构他们的代码。这的长期后果是它助长了坏习惯。“嗯，我应该把它拆分成一个单独的文件，但是呃……不，那太痛苦了，我现在要把代码加在这里。”

至于剩下的构建系统，仅用于绑定，维护它们似乎并没有那么糟糕——反正接触该代码的人通常都很熟悉它们。那里的挑战是除了其中一个 (QMake) 之外，所有这些都缺乏 pkg-config 集成。这意味着包含路径、库路径和要链接的库最终会在多个地方重复。当链接使用内部其他库的静态库时，这尤其棘手，这通常是我们的语言绑定使用 frida-core 的方式。

## 新功能

此版本中有相当多令人兴奋的新事物：

- gumjs: 添加 Process.runOnThread()，以便轻松在特定线程上运行任意代码。必须小心使用以避免死锁/重入问题。
- gumjs: 向 Thread.backtrace() 添加 *limit* 选项。感谢 [@davinci-tech][]！
- gumjs: 使用已弃用 API 的替代方案扩展 CModule glib.h。
- stalker: 添加 StalkerIterator.put_chaining_return()。感谢 [@s1341][]！
- stalker: 添加 run_on_thread() 和 run_on_thread_sync()。
- interceptor: 添加对 x86 上影子堆栈的支持。感谢 [@yjugl][]！
- cpu-features: 添加 CET_SS 标志和检测逻辑。感谢 [@yjugl][]！
- x86-writer: 添加 cpu_features 字段。感谢 [@yjugl][]！
- spinlock: 添加 try_acquire()。感谢 [@mrmacete][]！
- cloak: 添加 with_lock_held() 和 is_locked()。感谢 [@mrmacete][]！
- interceptor: 添加 with_lock_held() 和 is_locked()。感谢 [@mrmacete][]！
- darwin: 当助手崩溃时提示 macOS 引导参数。
- java: 支持实例化没有构造函数的类。感谢 [@AeonLucid][]！
- java: 添加对数组的数组的支持。感谢 [@histausse][]！
- python: 使源代码分发完全可以从源代码构建，而不是仅支持使用 devkit 构建。
- python: 放弃 MSVS 构建系统。
- node: 添加 Meson 构建系统，放弃 prebuild 和 node-gyp 位。
- node: 支持在找不到预构建时完全从源代码构建。
- clr: 添加 Meson 构建系统，放弃 MSVS 构建系统。
- qml: 添加 Meson 构建系统，放弃 qmake 构建系统。
- qml: 添加对 Qt 6 的支持。感谢 [@zaxo7][]！
- qml: 放弃对 Qt 5 的支持。

## 错误修复

最后但并非最不重要的一点是，我们还为您带来了一长串质量改进：

- gumjs: 在 NativeCallback 调用中保留线程的系统错误。感谢 [@HexKitchen][]！
- gumjs: 始终向 NativeCallback 公开线程的系统错误。
- gumjs: 堵塞 Stalker 实例的泄漏。
- stalker: 修复 arm64 上破坏独占访问的块事件。感谢 [@saicao][]！
- memory: 修复 RWX 系统上的 patch_code() 保护翻转。
- swift-api-resolver: 修复间接类型条目的处理。
- swift: 解决 iOS 模拟器上的 Module.load() 问题。感谢 [@zydeco][]！
- base: 修复自定义 GSource 实现中的竞争性崩溃。
- base: 修复 p2p AgentSession 注册逻辑。
- buffer: 修复 read_string() 大小逻辑。感谢 [@hsorbo][]！
- linux: 修复某些 32 位系统上的早期插桩。
- linux: 修复现代 Android 上的 inject_library_blob()。
- linux: 修复不可靠的 exec 过渡逻辑。
- linux: 修复 libc 缺失时不可靠的注入。
- agent: 修复 child-gating fork() 场景中的挂起。在 pidfd_getfd() 可用但不允许的情况下可重现，例如在 Docker 容器内。
- windows: 使用 RW/RX 权限进行注入。这使得 Frida 注入与更多软件兼容。特别是，如果起始地址是 RWX，Mozilla Firefox 会拒绝线程启动。感谢 [@yjugl][]！
- darwin: 在 Frida hook 周围按摩 libunwind，以避免破坏使用异常的代码，例如通过 Objective-C 中的 @try/@catch。感谢 [@mrmacete][]！
- darwin: 在 ThreadSuspendMonitor 中获取 Interceptor 和 Cloak 锁，以扩展其范围以防止持有 Cloak 或 Interceptor 锁的线程被挂起的死锁情况。感谢 [@mrmacete][]！
- darwin: 修复 InjectInstance 调度源的竞争性拆卸。
- darwin: 修复 SpawnInstance 调度源的竞争性拆卸。
- android: 修复 execl() 及其朋友的 child-gating。
- compiler: 升级 @types/frida-gum。感谢 [@s1341][]！
- modulate: 优雅地处理丢失的符号。感谢 [@hsorbo][]！
- python: 将 _frida 包移动到 frida 包内。

## EOF

这几乎总结了它。享受吧！


[here]: https://github.com/frida/releng?tab=readme-ov-file#setting-up-a-new-project
[@davinci-tech]: https://github.com/davinci-tech
[@s1341]: https://github.com/s1341
[@yjugl]: https://github.com/yjugl
[@mrmacete]: https://twitter.com/bezjaje
[@AeonLucid]: https://twitter.com/AeonLucid
[@histausse]: https://github.com/histausse
[@zaxo7]: https://github.com/zaxo7
[@HexKitchen]: https://github.com/HexKitchen
[@saicao]: https://github.com/saicao
[@zydeco]: https://github.com/zydeco
[@hsorbo]: https://twitter.com/hsorbo
