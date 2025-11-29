## Frida 的演讲

我们在世界各地的各种会议上介绍了 Frida。随着演示材料的可用，我们将尝试将其放在这里。

- [OSDC 2015](https://web.archive.org/web/20160803154827/http://act.osdc.no/osdc2015no/):
  [Putting the open back into closed software](https://web.archive.org/web/20160805115358/https://act.osdc.no/osdc2015no/talk/6165)
  ([PDF]({{ site.baseurl_root }}/slides/osdc-2015-putting-the-open-back-into-closed-software.pdf) · [Recording](https://youtu.be/tmpjftTHzH8))

  有一个你渴望窥视其内部的黑盒进程吗？这个进程也许运行在你的手机上，或者在一个闭源操作系统上，而你必须与它进行互操作？这个专有软件背后的公司是否在 API 和文档方面不太坦诚？
  好吧，如果你懂一点 JavaScript 并且有一点毅力，也许我们可以提供帮助……

  在本次演讲中，我们将展示你可以用 Frida 做什么，Frida 是一个适用于 Windows、Mac、Linux、iOS、Android 和 QNX 的可编写脚本的动态二进制插桩工具包。我们通过示例展示了如何用 JavaScript 编写自定义调试代码片段，然后将这些脚本动态插入到正在运行的进程中。Hook 任何函数，监视加密 API 或跟踪私有应用程序代码。无需源代码，无需许可！

- [OSDC 2015](https://web.archive.org/web/20160803154827/http://act.osdc.no/osdc2015no/):
  [The engineering behind the reverse engineering](https://web.archive.org/web/20160413183418/http://act.osdc.no/osdc2015no/talk/6195)
  ([PDF]({{ site.baseurl_root }}/slides/osdc-2015-the-engineering-behind-the-reverse-engineering.pdf) · [Recording](https://youtu.be/uc1mbN9EJKQ))

  有没有想过如何构建自己的调试器？你十几岁时完成过汇编教程，但从未发现低级编程的任何实际用途？需要学习更多听起来很可怕的技术术语来提高你的薪资等级吗？如果你对以上零个或多个问题的回答是“是”，你可能会对我们提供的内容感兴趣。

  在本次演讲中，我们将深入探讨 Frida 背后的工程原理，Frida 是一个多平台可编写脚本的动态二进制插桩工具包。我们解释操作系统进程的基础知识，以及相关的本机操作系统 API。我们展示如何使用这些 API 来探测目标进程的状态（内存、寄存器、线程），以及如何将你自己的代码注入到该进程中。如果时间允许，我们将展示 Frida 如何通过在内存中重写二进制代码来执行其动态插桩，而目标进程正在运行。

- [NLUUG 2015](https://www.nluug.nl/activiteiten/events/nj15/index.html):
  [Frida: Putting the open back into closed software](https://www.nluug.nl/activiteiten/events/nj15/abstracts/ab08.html)
  ([Slides](https://slides.com/oleavr/nluug-2015-frida-putting-the-open-back-into-closed-software)
  · [Demos](https://github.com/frida/frida-presentations/tree/master/NLUUG2015)
  · [Recording](https://youtu.be/3lo1Y2oKkE4))

  有一个你渴望窥视其内部的黑盒进程吗？这个进程也许运行在你的手机上，或者在一个闭源操作系统上，而你必须与它进行互操作？这个专有软件背后的公司是否在 API 和文档方面不太坦诚？
  好吧，如果你懂一点 JavaScript 并且有一点毅力，也许我们可以提供帮助……

  在本次演讲中，我们将展示你可以用 Frida 做什么，Frida 是一个适用于 Windows、Mac、Linux、iOS、Android 和 QNX 的可编写脚本的动态二进制插桩工具包。我们通过示例展示了如何用 JavaScript 编写自定义调试代码片段，然后将这些脚本动态插入到正在运行的进程中。Hook 任何函数，监视加密 API 或跟踪私有应用程序代码。无需源代码，无需许可！

- [ZeroNights 2015](http://2015.zeronights.org/):
  [Cross-platform reversing with Frida](http://2015.zeronights.org/workshops.html)
  ([PDF]({{ site.baseurl_root }}/slides/zeronights-2015-cross-platform-reversing-with-frida.pdf)
  · [Demos](https://github.com/frida/frida-presentations/tree/master/ZeroNights2015))

  Frida 是一个可编写脚本的动态二进制插桩工具包，旨在大幅缩短动态分析和逆向工程工具的开发周期。它还附带了一些构建在其 API 之上的 CLI 工具。它用可移植的 C 编写，以商业友好的 OSS 许可证发布，具有 Python、Node.js 等语言绑定，是处理所有当前平台（Windows、Mac、Linux、iOS、Android 和 QNX）上二进制文件动态插桩的行业工具。

  本次研讨会面向希望快速了解桌面和移动设备上动态插桩最新技术的参与者。我们将从介绍 Frida 的 API 和 CLI 工具开始，然后带你从头开始构建一个逆向工具。

  研讨会参与者的要求：

  - 2-3 小时
  - 英语知识
  - 如果你带一台运行 Windows、Mac 或 Linux 的笔记本电脑，以及可选的一台已越狱/root 的 iOS 或 Android 设备，那就太好了

- [No cON Name 2015](https://www.noconname.org/):
  [Cross-platform reversing with Frida](https://www.noconname.org/)
  ([PDF]({{ site.baseurl_root }}/slides/ncn-2015-cross-platform-reversing-with-frida.pdf)
  · [Demos](https://github.com/frida/frida-presentations/tree/master/NcN2015))

  Frida 是一个可编写脚本的动态二进制插桩工具包，旨在大幅缩短动态分析和逆向工程工具的开发周期。它还附带了一些构建在其 API 之上的 CLI 工具。它用可移植的 C 编写，以商业友好的 OSS 许可证发布，具有 Python、Node.js 等语言绑定，是处理所有当前平台（Windows、Mac、Linux、iOS、Android 和 QNX）上二进制文件动态插桩的行业工具。

  本次研讨会面向希望快速了解桌面和移动设备上动态插桩最新技术的参与者。我们将从介绍 Frida 的 API 和 CLI 工具开始，然后带你从头开始构建一个逆向工具。

  研讨会参与者的要求：

  - 2 小时
  - 英语知识
  - 如果你带一台运行 Windows、Mac 或 Linux 的笔记本电脑，以及可选的一台已越狱/root 的 iOS 或 Android 设备，那就太好了

- [FOSDEM 2016](https://fosdem.org/2016/schedule/track/testing_and_automation/):
  [Testing interoperability with closed-source software through scriptable diplomacy](https://fosdem.org/2016/schedule/event/closed_source_interop/)
  ([PDF]({{ site.baseurl_root }}/slides/fosdem-2016-testing-interoperability-with-closed-source-software-through-scriptable-diplomacy.pdf))

  你当然编写开源软件。他们没有。为了你的移动用户的利益，你们都需要成为朋友。进入 Frida，外交官（她实际上只是一个库，但不要告诉任何人）。她拥有哄骗的超能力，允许你通过暴露仅有二进制文件的软件的内部结构，无论是其他库、操作系统，还是你必须处理的其他 OS 进程。你可以编程 Frida 渗透闭源软件，并将其内部结构暴露为你可以用来测试软件互操作性的抽象。想将他们的一些逻辑提升到你的 mock 中吗？或者用你的 mock 替换他们二进制代码中的几个函数？希望你想使用高级语言（如 JavaScript 和/或 Python）来做这件事，因为这些是 Frida 最喜欢的。

  在本次演讲中，我们使用 Frida（可编写脚本的动态插桩工具包）来暴露仅有二进制文件的软件的内部功能。通过暴露内部函数和数据结构，紧密集成的软件通常变得更容易以细粒度进行测试。以前必须依赖于几个正在运行的子系统的较大集成测试，稍加努力，就可以变成更容易推理的隔离测试夹具。我们向那些必须处理这种级别互操作性的不幸灵魂展示如何编程 Frida 以识别和暴露远程进程中的函数，以及如何以单元测试风格将这些暴露的函数组合成小型测试夹具。

- [BSides Knoxville](https://bsidesknoxville.com/):
  [Peeking under the hood with Frida](https://bsidesknoxville2016.sched.org/event/6tCd/peeking-under-the-hood-with-frida)
  ([Recording](https://youtu.be/RINNW4xOWL8))

  有没有想过窥视运行在桌面或智能手机上的应用程序的底层？想知道传递给特定加密函数的数据是什么？Frida 适合你！

  Frida 是一个强大而现代的二进制插桩框架，它使得 hook 和跟踪目标可执行文件中的任意函数变得简单，并使用易于编写的 javascript 探索其功能。它就像二进制应用程序的 greasemonkey！它支持 Windows、Linux、OSX、iOS、Android 和 QNX。

  本次演讲将介绍 Frida 并展示如何使用它来辅助二进制应用程序的分析。它将包含大量演示。

  如果时间允许，我们还将讨论将 Frida 移植到 QNX 所需的一些工作。

- [Ekoparty 2016](https://www.ekoparty.org/):
  [Getting fun with Frida](https://www.coresecurity.com/publication/getting-fun-frida)

  你知道 Frida 是什么吗？你知道它是关于什么的吗？有什么用？不，我不是在说那位著名的画家。我说的是一个新的 hook 和动态二进制插桩框架。

  在这个快速演讲中，我打算向你展示这个新可用的框架，以促进一些日常逆向工程任务。我将教你它的基本部分是什么，为什么它对你有用，与其他类似框架相比有哪些优缺点，以及如何通过一些演示和代码片段使用它。

- [RMLL 2017](https://2017.rmll.info/en/):
  [Unlocking secrets of proprietary software using Frida](https://prog2017.rmll.info/programme/securite-entre-transparence-et-opacite/devoilons-les-secrets-des-logiciels-proprietaires-avec-frida?lang=en)
  ([Slides](http://slides.com/oleavr/frida-rmll-2017)
  · [Recording](https://rmll.ubicast.tv/videos/frida_03038/))

  有没有想过了解运行在桌面或手机上的应用程序的内部结构？想知道传递给特定加密函数的数据是什么？那么 Frida 适合你！

  本次演讲将介绍 Frida 并展示如何使用它来辅助二进制应用程序的分析。它将包含大量演示。

- [GPN 2018](https://entropia.de/GPN18):
  [Frida - (Game)Hacking mit JavaScript](https://www.youtube.com/watch?v=6QpRD3tkw48) (German presentation)

  每个人都知道 JavaScript。但是有多少人知道 JavaScript 也可以很好地用于破解游戏或程序？我介绍 Frida 框架，它正是实现了这一点！

  Frida 是一个允许将 JavaScript 加载到进程中的框架。为此，V8 JavaScript 解释器被加载到一个进程中，该进程带来了各种功能。内存操作、Hooks、Detours，一切皆有可能！
