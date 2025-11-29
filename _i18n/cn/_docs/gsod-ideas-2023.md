# 规划更新 Frida 文档

_规划如何让 Frida 文档变得更好_

本文档检查了 Frida 文档的当前状态，并讨论了如何使其变得更好。

## 文档和支持的当前状态

### 文档的当前可用性

1. [官方 Frida 文档 (frida.re/docs)](https://frida.re/docs/)  TODO: 描述文档中目前的内容。
1. [Learn Frida and Frida Handbook](https://learnfrida.info/)，作者 [Fernando Diaz](https://learnfrida.info/about_faq/)。
该网站有在线文档 (HTML)，并且可以从同一网站以及 NowSecure Academy 网站自由访问该书。
1. _其他位置？_

### 用户支持

1. 用户可以在 [Telegram 上获得 Frida 支持](https://frida.re/contact/)。目前有 2720 名成员。_Frida OffTopic_ 有 457 名成员。
1. 用户可以在 [IRC/Freenode #frida 上获得 Frida 支持](https://frida.re/contact/)。频道上只有不到十个人，可能由于 Freenode 和 Libera 之间的分裂而不活跃。
1. Libera Chat 上有一个 #frida 频道。我访问时该频道有 13 个用户。frida.re 网站上尚未列出该频道的存在。
1. [github/frida/frida 上的 Github Issues](https://github.com/frida/frida/issues)。Github Issues 被（滥）用作帮助场所。
1. [Discord Frida Server](https://discord.gg/J7VCWhZQ5N)。180 名成员，我上次访问时有 40 人在线（欧盟时区）。

## 理由（用于更新 Frida 文档）

每个免费/开源项目都应该让人们知道和理解它的作用。这增强了可行性，并可能为项目带来更多贡献者。

维护项目最困难的部分是软件开发方面。文档和社区的发展更容易，不应被忽视。

## 本文档的受众类型

文档应迎合以下用户群体

1. 具有其他计算机相关任务经验并希望扩展到 Frida 的高级用户。
   在解释 Frida 时，文档应与他们先前的知识联系起来。
1. 具有 Frida 经验并希望查阅文档以快速提醒某些任务的用户。
   文档不应仅以截屏视频的形式存在，而应以文本形式存在，以便轻松复制粘贴复杂的命令。命令应该易于识别。当您选择一行时，它不应选择 Unix 提示符。
1. 计算机经验很少但愿意努力学习的用户。
   他们应该很好地理解 Frida 的作用，能够成功设置 Frida，并至少执行一项简单的任务。
1. 对 Frida 的应用感兴趣但会要求其他人承担任务/工作的用户。
   他们应该能够很好地理解 Frida 的作用，并能够大致评估任务/工作的难度。

## 文档的目的

* 避免支持渠道上的重复问题。
* 展示常见任务的最佳实践。
* 涵盖各种操作系统上的初始成功安装。包括故障排除。包括验证安装是否成功的简单验证任务。
* 文档应该可以通过搜索引擎访问。大多数用户在搜索引擎上搜索。常见搜索应指向文档。它也会被那些 AI 搜索引擎获取。

## 新文档中应该包含什么

* 讨论文章：Frida 到底是什么？_访问正在运行的软件的地址空间_的类型。以 _Cheat Engine_ 为例。Cheat Engine 对数据段进行读/写/设置以更改生命数或硬币数。较新的 Cheat Engine [也进行代码注入，使用汇编！](https://wiki.cheatengine.org/index.php?title=Tutorials:Auto_Assembler:Injection_full)。
* 讨论文章：Frida 到底是什么？使用 Greasemonkey/Tampermonkey/Violentmonkey 进行实际解释。实际上，[Violentmonkey](https://github.com/violentmonkey/violentmonkey) 是开发活跃的一个。
* 安装，Windows/Linux/OSX 的一般说明，每个主要 OS 版本的单独文章，带有故障排除部分和验证其安装成功的验证示例。单独的文章存在是为了让搜索引擎可以获取它们并供新用户使用。
* 参考文章：assets 中的那些不同包是什么，https://github.com/frida/frida/releases（即 _code devkit_, _gum devkit_,...）
* Android：如何在已 root 的手机上设置 Frida
* Android：如何将 Gadget 注入 APK，首先如何从手机获取 APK。[使用 apk.sh](https://github.com/ax/apk.sh)。
* Code Share：解释如何使用 https://codeshare.frida.re/，如何贡献，
* 桌面：展示如何在三个主要桌面上使用 Frida。
* _TODO_

## TODO

* 在 https://github.com/frida/frida/issues 上创建新 Issue 时添加文档。指导如何为错误报告收集更好的信息。应该说明这不是支持场所。
* 使用论坛软件？也许不是 discord（围墙花园，搜索引擎无法访问）。[像 StackExchange 一样管理](https://area51.stackexchange.com/) 或 [像 Discourse 一样自托管](https://github.com/discourse/discourse)。


## Google 文档季的组织提案

[关于创建组织提案的一般说明](https://developers.google.com/season-of-docs/docs/organization-application-hints)。

我们遵循 https://developers.google.com/season-of-docs/docs/org-proposal-template 上的模板

提案现在开始：

## 更新 Frida 的网站文档

### 关于您的组织

[Frida](https://frida.re)（当前版本 16.0.11，2013 年首次发布）是一个 wxWindows Library Licence 许可的动态代码插桩软件工具包。它附加到正在运行的软件，并让您访问执行流和数据。它允许您注入用 Javascript 编写的自己的代码，以便您可以修改软件的运行方式。Frida 通常用于计算机安全领域的逆向工程，例如 [Google Project Zero 的这个案例](https://googleprojectzero.blogspot.com/2022/01/zooming-in-on-zero-click-exploits.html)。Frida 是逆向工程 Android 和 iOS 移动应用程序的首选工具。此外，Frida 还用于软件测试、调试和软件开发。Frida 目前支持九种操作系统和三种架构系列（Intel, ARM, MIPS）。最后，Frida 是该领域最受欢迎的软件。

### 关于您的项目

[官方 Frida 文档](https://frida.re/docs/) 需要重组和扩展。它是由高级用户编写的，对新用户来说太简略了。新用户最终会在项目的 github issues 上提问（每周大约十个问题）。有一个拥有 2730 名用户的 Telegram 频道，但很难提供支持；给出的任何答案都很难被下一个问同样问题的人发现。

需要创建一个摩擦日志，帮助识别知识差距并提供故障排除文档。用例应包括在许多受支持的操作系统上设置 Frida，并提供验证设置是否有效的步骤。应提供讨论文档，向不同技术经验和背景水平的受众解释 Frida 的作用。

Frida 是安全研究人员使用的工具之一。有一个此类开源安全工具的生态系统，包括 AFL++（安全模糊测试），ghidra（反编译）。安全研究人员将使用其中一种或混合使用这些工具来完成任务。通过改进文档，Frida 将在支持生态系统和发展自己的社区方面处于更有利的地位。

### 您的项目范围

Frida 项目将：

* 审计现有文档并为三个主要用例（为不同操作系统设置 Frida，使用 Frida gadget 设置 Frida，以及使用 Frida 的常见任务）创建摩擦日志。
* 使用摩擦日志作为了解文档差距的指南，为主要用例创建更新的文档。
* 创建一个快速“备忘单”，帮助新用户快速有效地安装和使用 Frida。
* 整合来自文档测试人员（项目中的志愿者）和更广泛的 Frida 社区的反馈。
* 与发布团队合作更新 Frida 网站上的文档，并创建一个流程以使文档与更新工具保持同步。
* 为 Github Issues 创建问题模板，以便用户如果提出支持问题，将被重定向到官方文档和支持站点。添加用于报告错误和功能请求的模板。
* 浏览 1300 个 Github issues 并适当标记那些是支持请求的问题。用作文档中的输入。
* 包括 Github Releases 中不同类型资产的文档以及应如何使用它们。
* 将 https://codeshare.frida.re/ 纳入 Frida 文档。

本项目范围之外的工作：

* 本项目不会为 Frida 的代码贡献生成详细文档。

我们有一位该项目的强大技术写作候选人，我们估计这项工作将需要六个月才能完成。@simos 已承诺支持该项目。

### 衡量您的项目的成功

如果在发布新文档后出现以下情况，我们将认为该项目是成功的：

* 90% 的新用户问题得到覆盖。
* 实际上是支持请求的 Github issues 数量下降到每周两个。

### 时间表

该项目本身大约需要六个月才能完成。一旦聘请了技术作家，我们将花一个月的时间进行技术作家入职培训，然后进入审计和摩擦日志，并在最后几个月专注于创建文档。

|日期 	               |行动项目                                               |
|-----------------------|-----------------------------------------------------------|
|五月 	                  |入职培训                                                |
|六月 - 七月    	      |审计现有文档并创建摩擦日志       |
|八月 - 十月     	|创建文档                                       |
|十一月 	            |项目完成                                         |

### 项目预算

|预算项目 	                   |预算 (USD)                |实际 (USD)      | 备注    |
|---------------------------------|------------------------------|------------------|----------|
|技术作家                 |$12,000                       | $12,000          |          |
|志愿者津贴 (3 x $500)    |$1,500                        | $13,500          | 用于将密切提供信息和/或审查交付成果的志愿者 |
|志愿者 T 恤       	 |$200                          | $13,700          | 打印并交付给有文档贡献的志愿者 |
|总计                             |                              | $13,700          |
