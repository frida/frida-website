---
layout: news_item
title: 'Frida 17.2.0 发布'
date: 2025-06-18 23:35:07 +0200
author: oleavr
version: 17.2.0
categories: [release]
---

我很高兴宣布 Frida 17.2.0 的发布。此版本专注于使包发现变得极其简单。

这就是发现现有 Frida 特定包是多么容易：

![显示 frida-pm 搜索结果的终端](/img/frida-pm-search.png)

使用其中任何一个也同样容易：

![显示 frida-pm 安装结果的终端](/img/frida-pm-install.png)

**亮点**

- 🔍 **frida-pm search** – 零噪音结果 (通过 `keywords:frida-gum` 过滤)。
- 📦 **一键安装** – `frida-pm install <pkg>` 即使没有 Node.js 也能工作。
- 🧩 **编程 API** – 来自 Python、C 等的相同界面。

你在这里看到的是 frida-pm CLI 工具，在 frida-tools 14.2.0 中引入。它只有不到 300 行 Python 代码，因为它只是底层 `Frida.PackageManager` 实现的一个薄包装。

高级用户和包维护者通常仍会使用 npm/yarn/etc.，但我觉得要求初次使用 Frida 的用户也熟悉庞大的 JavaScript 生态系统可能会让他们感到不知所措和困惑。

frida-pm / Frida.PackageManager 的妙处在于搜索只显示 Frida 特定的包。这是通过将 `keywords:frida-gum` 烘焙到搜索查询中来实现的。

对于那些维护 Frida 特定包的人，请确保将 `frida-gum` 添加到 package.json 的 `keywords` 字段中。如果你的包是语言/运行时桥接器，请确保也添加 `frida-gum-bridge`。

因此，可发现性是这里的关键功能之一。另一个是它可以在没有 Node.js + npm 的系统上运行。虽然我们确实使用 npm 的注册表作为默认后端，但你可以将其指向你喜欢的任何注册表。

你还可以通过编程方式访问所有功能。例如，如果你想使用 Python 绑定进行搜索：

{% highlight py %}
import frida

pm = frida.PackageManager()
result = pm.search("il2cpp", limit=3)
print(result)
print(result.packages)
{% endhighlight %}

你会看到类似这样的内容：

{% highlight bash %}
$ python search.py
PackageSearchResult(packages=[<3 packages>], total=13)
[Package(name="frida-il2cpp-bridge", version="0.12.0", description="A Frida module to dump, trace or hijack any Il2Cpp application at runtime, without needing the global-metadata.dat file.", url="https://npm.im/frida-il2cpp-bridge"),
 Package(name="frida-objc-bridge", version="8.0.5", description="Objective-C runtime interop from Frida", url="https://npm.im/frida-objc-bridge"),
 Package(name="frida-java-bridge", version="7.0.4", description="Java runtime interop from Frida", url="https://npm.im/frida-java-bridge")]
$
{% endhighlight %}

或者也许你想安装几个包：

{% highlight py %}
import frida

pm = frida.PackageManager()
result = pm.install(specs=["frida-java-bridge@7.0.4", "frida-il2cpp-bridge"])
print(result)
print(result.packages)
{% endhighlight %}

运行时可能看起来像这样：

{% highlight bash %}
$ python install.py
PackageInstallResult(packages=[<2 packages>])
[Package(name="frida-java-bridge", version="7.0.4", description="Java runtime interop from Frida"),
 Package(name="frida-il2cpp-bridge", version="0.12.0", description="A Frida module to dump, trace or hijack any Il2Cpp application at runtime, without needing the global-metadata.dat file.")]
$
{% endhighlight %}

添加安装进度也很容易：

{% highlight py %}
import frida

def on_install_progress(phase, fraction, details):
    print({
        "phase": phase,
        "fraction": fraction,
        "details": details,
    })

pm = frida.PackageManager()
pm.on("install-progress", on_install_progress)
result = pm.install(specs=["frida-java-bridge", "frida-il2cpp-bridge"])
print(result)
print(result.packages)
{% endhighlight %}

这可能看起来像这样：

{% highlight bash %}
$ python install.py
{'phase': 'initializing', 'fraction': 0.0, 'details': None}
{'phase': 'preparing-dependencies', 'fraction': 0.05, 'details': None}
{'phase': 'resolving-package',
 'fraction': -1.0,
 'details': 'frida-java-bridge@latest'}
…
{% endhighlight %}

既然我们已经看了从 Python 使用 PackageManager API，我可能应该提到从 C 使用此 API 也（几乎）一样容易：

{% highlight c %}
#include <frida-core.h>

int
main (int argc,
      char * argv[])
{
  GCancellable * cancellable = NULL;
  GError * error = NULL;

  frida_init ();

  FridaPackageManager * manager = frida_package_manager_new ();

  FridaPackageInstallOptions * opts = frida_package_install_options_new ();
  frida_package_install_options_add_spec (opts, "frida-java-bridge@7.0.4");
  frida_package_install_options_add_spec (opts, "frida-il2cpp-bridge");

  frida_package_manager_install_sync (manager, opts, cancellable, &error);
  if (error != NULL)
    g_printerr ("%s\n", error->message);

  return (error == NULL) ? 0 : 1;
}
{% endhighlight %}

如果你想尝试这个例子，请从我们的 [releases][] 获取 frida-core devkit。

你可以像这样构建并运行它：

{% highlight bash %}
$ gcc install.c -o install -I. -L. -lfrida-core -Wl,--gc-sections
$ ./install
{% endhighlight %}

(frida-core-example.c 的顶部有一个针对 devkit 所针对的特定 OS/arch 定制的示例命令行。)

请注意，可以通过传递 NULL 省略 `opts`，在这种情况下，如果 package.json 中定义的包尚未安装或版本不匹配，则会安装它们。就像 npm 一样，如果你没有 package.json 文件并直接安装一些包，它会为你创建一个 package.json。

此版本还包括其他一些改进和修复：

- **Compiler**:
  - 将 `@frida/net` 升级到 5.0.0。
  - 修复缺少的 shim 资产 (感谢 [@imlihe][])。

- **frida-node**:
  - 更改 `Device.openChannel()` 的返回类型以公开带有 `destroy()` 的更具体的类型。

要升级，请运行：

{% highlight bash %}
$ pip install --upgrade frida frida-tools
{% endhighlight %}

享受吧！


[releases]: https://github.com/frida/frida/releases
[@imlihe]: https://github.com/imlihe
