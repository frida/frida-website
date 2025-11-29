Frida 诞生于 [@oleavr][] 和 [@hsorbo][] 随意头脑风暴之后，他们希望能够将繁琐的手动逆向工程转变为更有趣、更高效和更具交互性的工作。

在构建了 [oSpy][] 和其他自定义工具来解决逆向工程的痛点之后，[@oleavr][] 开始拼凑 [frida-gum][]，这是一个通用的跨平台 C 代码插桩库。当时它仅限于 hook 函数并提供一些工具来帮助开发人员编写针对内存泄漏的单元测试和在极细粒度级别上进行分析。后来它被进一步改进并用于创建 Frida。组件 [frida-core][] 将负责将共享库注入任意进程的所有细节，并与在该进程内运行的注入代码保持实时的双向通道。在该 payload 内部，[frida-gum][] 将负责 hook 函数并使用优秀的 [QuickJS][] 引擎提供脚本运行时。

后来，在他们并不充裕的业余时间里，[@oleavr][] 和 [@karltk][] 进行了一些娱乐性的结对编程黑客马拉松，这导致了 [frida-gum][] 的代码跟踪引擎（即所谓的 [Stalker][]）的 [巨大改进][huge improvements]。还创建了 Python 绑定。他们开始意识到是时候让外面的人知道这个项目了，因此进一步的黑客马拉松致力于拼凑一个网站和一些急需的文档。

今天，对于任何对动态插桩和/或逆向工程感兴趣的人来说，Frida 应该是一个非常有用的工具箱。现在有 [Node.js][]、[Python][]、[Swift][]、[.NET][]、[Qt/Qml][]、[Go][] 的语言绑定，也可以从 C 使用 Frida。


[@oleavr]: https://twitter.com/oleavr
[@hsorbo]: https://twitter.com/hsorbo
[@karltk]: https://twitter.com/karltk
[frida-core]: https://github.com/frida/frida-core
[frida-gum]: https://github.com/frida/frida-gum
[Stalker]: https://github.com/frida/frida-gum/blob/master/gum/backend-x86/gumstalker-x86.c
[huge improvements]: http://blog.kalleberg.org/post/833101026/live-x86-code-instrumentation-with-frida
[Node.js]: https://github.com/frida/frida-node
[Python]: https://github.com/frida/frida-python
[Swift]: https://github.com/frida/frida-swift
[.NET]: https://github.com/frida/frida-clr
[Qt/Qml]: https://github.com/frida/frida-qml
[Go]: https://github.com/frida/frida-go
[oSpy]: https://github.com/oleavr/ospy
[QuickJS]: https://bellard.org/quickjs/
