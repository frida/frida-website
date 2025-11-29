本网站旨在成为 Frida 的综合指南。我们将涵盖诸如从命令行进行交互式函数跟踪、在 Frida 的 API 之上构建自己的工具等主题，并为您参与 Frida 本身的未来开发提供一些建议。

## 那么 Frida 到底是什么？

它是原生应用的 [Greasemonkey](https://addons.mozilla.org/en-US/firefox/addon/greasemonkey/)，或者用更专业的术语来说，它是一个动态代码插桩工具包。它允许您将 JavaScript 片段或您自己的库注入到 Windows、macOS、GNU/Linux、iOS、watchOS、tvOS、Android、FreeBSD 和 QNX 上的原生应用中。Frida 还为您提供了一些基于 Frida API 构建的简单工具。这些工具可以直接使用，根据您的需要进行调整，或者作为如何使用 API 的示例。

## 为什么我需要这个？

好问题。我们将尝试通过一些用例来阐明：

- 有一个新的热门应用大家都非常兴奋，但它只在 iOS 上可用，而您很想与它进行互操作。您意识到它依赖于加密的网络协议，像 Wireshark 这样的工具无法解决问题。您拿起 Frida 并使用它进行 API 跟踪。
- 您正在构建一个桌面应用，该应用已部署在客户现场。出现了一个问题，但内置的日志代码不够用。您需要向客户发送一个包含大量昂贵日志代码的自定义构建版本。然后您意识到您可以只使用 Frida 并构建一个特定于应用的工具，该工具将添加您需要的所有诊断信息，而且只需几行 Python 代码。无需向客户发送新的自定义构建版本 - 您只需发送该工具，它将在您应用的许多版本上工作。
- 您想构建一个增强版的 Wireshark，支持嗅探加密协议。它甚至可以操纵函数调用来伪造网络条件，否则这需要您建立一个测试实验室。
- 您的内部应用可以使用一些黑盒测试，而无需用仅用于奇异测试的逻辑污染您的生产代码。

## 为什么是 Python API，但调试逻辑却是 JavaScript？

Frida 的核心是用 C 编写的，并将 [QuickJS](https://bellard.org/quickjs/) 注入到目标进程中，在那里您的 JS 可以完全访问内存、hook 函数甚至调用进程内的原生函数。有一个双向通信通道，用于在您的应用和在目标进程内运行的 JS 之间进行对话。

使用 Python 和 JS 允许使用无风险的 API 进行快速开发。Frida 可以帮助您轻松捕获 JS 中的错误并为您提供异常而不是崩溃。

不想用 Python 写？没问题。您可以直接从 C 使用 Frida，在这个 C 核心之上还有多种语言绑定，例如 [Node.js](https://github.com/frida/frida-node)、[Python](https://github.com/frida/frida-python)、[Swift](https://github.com/frida/frida-swift)、[.NET](https://github.com/frida/frida-clr)、[Qml](https://github.com/frida/frida-qml)、[Go](https://github.com/frida/frida-go) 等。为其他语言和环境构建额外的绑定非常容易。

## ProTips™、注意和警告

在本指南中，有许多小而有用的信息，可以使使用 Frida 更容易、更有趣且更少危险。以下是需要注意的事项。

<div class="note">
  <h5>ProTips™ 帮助您从 Frida 获得更多</h5>
  <p>这些提示和技巧将帮助您成为 Frida 向导！</p>
</div>

<div class="note info">
  <h5>注意是有用的信息片段</h5>
  <p>这些是理解 Frida 有时需要的额外信息。</p>
</div>

<div class="note warning">
  <h5>警告帮助您不要搞砸事情</h5>
  <p>如果您希望避免某些死亡，请注意这些消息。</p>
</div>

如果您在途中遇到任何我们未涵盖的内容，或者如果您知道您认为其他人会觉得有用的提示，请[提交 issue]({{ site.organization_url }}/frida-website/issues/new)，我们将考虑将其包含在本指南中。
