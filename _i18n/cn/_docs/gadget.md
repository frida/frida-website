Frida 的 Gadget 是一个共享库，旨在当[注入][]操作模式不适用时，由要插桩的程序加载。

这可以通过多种方式完成，例如：

-   修改程序的源代码
-   修补它或其库之一，例如使用像 [insert_dylib][] 这样的工具
-   使用像 *LD_PRELOAD* 或 *DYLD_INSERT_LIBRARIES* 这样的动态链接器功能

一旦动态链接器执行其构造函数，Gadget 就会启动。

它支持四种不同的交互，具体取决于您的用例，其中 [Listen](#listen) 交互是默认的。您可以通过添加配置文件来覆盖此设置。该文件的命名应与 Gadget 二进制文件完全相同，但文件扩展名为 *.config*。例如，如果您将二进制文件命名为 *FridaGadget.dylib*，则应将配置文件命名为 *FridaGadget.config*。

请注意，您可以随意命名 Gadget 二进制文件，这对于躲避反 Frida 检测方案（查找名称中带有 "Frida" 的加载库）非常有用。

还值得注意的是，当使用 Xcode 将 .config 添加到 iOS 应用时，您可能会发现它倾向于将 *FridaGadget.dylib* 放在名为 “Frameworks” 的子目录中，而将 “.config” 放在其上级目录中 – 与应用的可执行文件和任何资源文件相邻。因此，在这种情况下，Gadget 也会在父目录中查找 .config。但前提是它被放在名为 “Frameworks” 的目录中。

在 Android 上，包管理器只会从不可调试应用程序的 `/lib` 目录复制文件，如果它们的名称符合以下条件：
- 以前缀 `lib` 开头
- 以后缀 `.so` 结尾
- 是 `gdbserver`

Frida 非常清楚这个限制，并将接受带有这些更改的配置文件。示例：
```
lib
└── arm64-v8a
    ├── libgadget.config.so
    ├── libgadget.so
```
有关更多信息，请查看[这篇文章](https://lief.quarkslab.com/doc/latest/tutorials/09_frida_lief.html#id9)。

配置文件应该是以 JSON 对象为根的 UTF-8 编码文本文件。它在根级别支持四个不同的键：

-   `interaction`: 描述要使用的交互的对象。默认为 [Listen](#listen) 交互。

-   `teardown`: 指定 `minimal` 或 `full` 的字符串，说明库卸载时要执行多少清理工作。默认为 `minimal`，这意味着我们不会关闭内部线程并释放分配的内存和操作系统资源。如果 Gadget 的生命周期与程序本身相关联，这很好。如果您打算在某个时候卸载它，请指定 `full`。

-   `runtime`: 指定 `default`、`qjs` 或 `v8` 的字符串，让您覆盖使用的默认 JavaScript 运行时。

-   `code_signing`: 指定 `optional` 或 `required` 的字符串，通过将其设置为 `required`，可以在没有附加调试器的情况下在未越狱的 iOS 设备上运行。默认为 `optional`，这意味着 Frida 将假定可以修改内存中的现有代码并运行未签名的代码，而不会被内核杀死。将其设置为 `required` 也意味着 Interceptor API 不可用。因此，在未越狱的 iOS 设备上使用 Interceptor API 的唯一方法是在加载 Gadget 之前附加调试器。请注意，只需使用调试器启动应用程序即可，它不必保持附加状态，因为宽松的代码签名状态一旦设置就会保持。

## 支持的交互类型

  1. [Listen](#listen)
  1. [Connect](#connect)
  1. [Script](#script)
  1. [ScriptDirectory](#scriptdirectory)

## Listen

这是默认交互，其中 Gadget 暴露一个兼容 *frida-server* 的接口，默认监听 *localhost:27042*。唯一的区别是正在运行的进程和已安装的应用列表仅包含一个条目，即程序本身。进程名称始终只是 *Gadget*，已安装应用的标识符始终是 *re.frida.Gadget*。

为了实现早期插桩，我们让 Gadget 的构造函数阻塞，直到您 *attach()* 到进程，或者在经过通常的 *spawn()* -> *attach()* -> *…应用插桩…* 步骤后调用 *resume()*。这意味着现有的 CLI 工具（如 [frida-trace](/docs/frida-trace/)）的工作方式与您已经使用它们的方式相同。

如果您不想要这种阻塞行为，并希望让程序直接启动，或者您更喜欢它在不同的接口或端口上监听，您可以通过配置文件自定义它。

默认配置为：

{% highlight json %}
{
  "interaction": {
    "type": "listen",
    "address": "127.0.0.1",
    "port": 27042,
    "on_port_conflict": "fail",
    "on_load": "wait"
  }
}
{% endhighlight %}

支持的配置键有：

-   `address`: 指定要监听的接口的字符串。支持 IPv4 和 IPv6。默认为 `127.0.0.1`。指定 `0.0.0.0` 以监听所有 IPv4 接口，`::` 以监听所有 IPv6 接口。

-   `port`: 指定要监听的 TCP 端口的数字。默认为 `27042`。

-   `certificate`: 指定此项以启用 TLS。必须是 PEM 编码的公钥和私钥，可以是包含多行 PEM 数据的字符串，也可以是指定要从中加载的文件系统路径的单行字符串。服务器将接受来自客户端的任何证书。

-   `token`: 指定此项以启用身份验证。必须是指定来自传入客户端的预期秘密令牌的字符串。

-   `on_port_conflict`: 指定 `fail` 或 `pick-next` 的字符串，说明如果监听端口已被占用该怎么办。默认为 `fail`，这意味着 Gadget 将启动失败。如果您希望它尝试每个连续端口直到找到可用端口，请指定 `pick-next`。

-   `on_load`: 指定 `resume` 或 `wait` 的字符串，说明加载 Gadget 时要做什么。默认为 `wait`，这意味着它将等待您连接到它并告诉它恢复。如果您希望允许程序立即启动，请指定 `resume`，如果您只想稍后附加，这很有用。

-   `origin`: 指定此项以通过要求 “Origin” 标头与此处指定的值匹配来防止来自 Web 浏览器的未经授权的跨域使用。

-   `asset_root`: 指定此项以通过 HTTP/HTTPS 提供静态文件，其中暴露指定目录内的任何可访问文件。默认情况下不提供文件。

## Connect

这是 “Listen” 交互的反面，Gadget 不是在 TCP 上监听，而是连接到正在运行的 *frida-portal* 并成为其进程集群中的一个节点。这就是它监听的所谓 *cluster* 接口。Portal 通常还暴露一个 *control* 接口，该接口使用与 *frida-server* 相同的协议。这允许任何连接的控制器 *enumerate_processes()* 并 *attach()* 到它们，就好像它们在运行 Portal 的机器本地一样。

为了实现早期插桩，我们让 Gadget 的构造函数阻塞，直到控制器请求 *resume()* – 但前提是启用了 spawn-gating。（通过 *Device.enable_spawn_gating()*。）这意味着对于简单的设置，Gadget 只会阻塞直到它连接到 Portal 并加入其集群 – 以便询问是否启用了 spawn-gating。

默认配置为：

{% highlight json %}
{
  "interaction": {
    "type": "connect",
    "address": "127.0.0.1",
    "port": 27052
  }
}
{% endhighlight %}

支持的配置键有：

-   `address`: 指定要连接的主机的字符串，即 Portal 的集群接口暴露的地方。支持 IPv4 和 IPv6。默认为 `127.0.0.1`。

-   `port`: 指定要连接的 TCP 端口的数字，在暴露 Portal 集群接口的主机上。默认为 `27052`。

-   `certificate`: 如果 Portal 启用了 TLS，则必须指定。包含 PEM 编码的公钥，可以是包含多行 PEM 数据的字符串，也可以是指定要从中加载的文件系统路径的单行字符串。这是受信任 CA 的公钥，服务器的证书必须匹配或派生自该公钥。

-   `token`: 如果 Portal 的集群接口启用了身份验证，则必须指定。这是指定要呈现给 Portal 的令牌的字符串。此字符串的实际解释取决于 Portal 实现，从 *frida-portal* 情况下的固定秘密，到 API 实例化 Portal 并插入自定义身份验证服务时的任何内容（例如 OAuth 访问令牌）。

-   `acl`: 指定访问控制列表的字符串数组，用于限制哪些控制器能够发现并与此进程交互。例如，如果是 `["team-a", "team-b"]`，则来自 “team-a” 或 “team-b” 的任何控制器都将被授予访问权限。仅当通过 API 实例化 Portal 时才应设置此键，因为需要自定义应用程序代码来 *标记* 要授予访问权限的控制器连接，通常基于某种自定义身份验证方案。

<div class="note">
  <h5>高级用户</h5>
  <p>
    为了获得更大的控制权，例如自定义身份验证、每节点 ACL 和特定于应用程序的协议消息，您也可以实例化 PortalService 对象，而不是运行 frida-portal CLI 程序。
  </p>
</div>

## Script

有时，通过在程序入口点执行之前从文件系统加载脚本，以完全自主的方式应用一些插桩是很有用的。

这是所需的最小配置：

{% highlight json %}
{
  "interaction": {
    "type": "script",
    "path": "/home/oleavr/explore.js"
  }
}
{% endhighlight %}

其中 *explore.js* 包含以下骨架：

{% highlight js %}
rpc.exports = {
  init(stage, parameters) {
    console.log('[init]', stage, JSON.stringify(parameters));

    Interceptor.attach(Module.getGlobalExportByName('open'), {
      onEnter(args) {
        const path = args[0].readUtf8String();
        console.log('open("' + path + '")');
      }
    });
  },
  dispose() {
    console.log('[dispose]');
  }
};
{% endhighlight %}

[rpc.exports][] 部分实际上是可选的，当您的脚本需要通过其生命周期感知时很有用。

Gadget 调用您的 `init()` 方法并等待其返回，然后再让程序执行其入口点。这意味着如果您需要执行某些异步操作（例如 [Socket.connect()][]），您可以返回一个 *Promise*，并保证您不会错过任何早期调用。
第一个参数 `stage` 是一个字符串，指定 `early` 或 `late`，用于了解 Gadget 是刚刚加载，还是脚本正在重新加载。下面有关于后一个主题的更多信息。
第二个参数 `parameters` 是配置文件中可选指定的对象，如果没有则为空对象。这对参数化您的脚本很有用。

如果您需要在卸载脚本时执行一些显式清理，您还可以暴露一个 `dispose()` 方法。这通常发生在进程退出、Gadget 被卸载或在从磁盘加载新版本之前卸载脚本时。

为了调试，您可以使用 *console.log()*、*console.warn()* 和 *console.error()*，它们将打印到 *stdout*/*stderr*。

支持的配置键有：

-   `path`: 指定要加载的脚本的文件系统路径的字符串。也可以是相对于 Gadget 二进制文件所在位置的路径。在 iOS 上指定相对路径将首先查找相对于应用 Documents 目录的脚本。这意味着您可以使用 iTunes 文件共享上传脚本的更新版本，或者通过 AFC 提供整个容器来更新它，这对于可调试的应用程序是允许的。这与 `"on_change": "reload"` 一起使用特别有用。
    此键没有默认值，必须提供。

-   `parameters`: 包含您希望传递给 `init()` RPC 方法的任意配置数据的对象。默认为空对象。

-   `on_change`: 指定 `ignore` 或 `reload` 的字符串，其中 `ignore` 表示脚本将仅加载一次，`reload` 表示 Gadget 将监视文件并在其更改时重新加载脚本。默认为 `ignore`，但强烈建议在开发期间使用 `reload`。

## ScriptDirectory

在某些情况下，您可能希望篡改系统范围的程序和库，但与其从脚本逻辑中识别程序，不如进行一些最小的过滤，并根据 Gadget 运行所在的程序加载不同的脚本。您甚至可能不需要任何过滤，但发现将每个脚本视为单独的插件很方便。在 GNU/Linux 系统上，此类脚本甚至可以由包提供，从而可以轻松安装对现有应用程序的调整。

这是所需的最小配置：

{% highlight json %}
{
  "interaction": {
    "type": "script-directory",
    "path": "/usr/local/frida/scripts"
  }
}
{% endhighlight %}

支持的配置键有：

-   `path`: 指定包含要加载的脚本的目录的文件系统路径的字符串。也可以是相对于 Gadget 二进制文件所在位置的路径。此键没有默认值，必须提供。
    脚本应使用 *.js* 作为其文件扩展名，每个脚本还可以在其旁边的 *.config* 文件中包含配置数据。这意味着
    *twitter.js* 可以在名为 *twitter.config* 的文件中指定其配置。

-   `on_change`: 指定 `ignore` 或 `rescan` 的字符串，其中 `ignore` 表示目录将仅扫描一次，`rescan` 表示 Gadget 将监视目录并在其更改时重新扫描。默认为 `ignore`，但强烈建议在开发期间使用 `rescan`。

每个脚本的可选配置文件可能包含以下键：

-   `filter`: 包含此脚本加载条件的对象。只需匹配其中一个，因此如果需要，应在脚本本身中实现复杂的过滤。支持以下键指定要匹配的内容：

    -   `executables`: 指定可执行文件名称的字符串数组
    -   `bundles`: 指定 bundle 标识符的字符串数组
    -   `objc_classes`: 指定 Objective-C 类名的字符串数组

-   `parameters`: 包含您希望传递给 `init()` RPC 方法的任意配置数据的对象。默认为空对象。

-   `on_change`: 指定 `ignore` 或 `reload` 的字符串，其中 `ignore` 表示脚本将仅加载一次，`reload` 表示 Gadget 将监视文件并在其更改时重新加载脚本。默认为 `ignore`，但强烈建议在开发期间使用 `reload`。

假设您想为 Twitter 的 macOS 应用编写一个调整，您可以在 */usr/local/frida/scripts* 中创建一个名为 *twitter.js* 的文件，其中包含：

{% highlight js %}
const { TMTheme } = ObjC.classes;

rpc.exports = {
  init(stage, parameters) {
    console.log('[init]', stage, JSON.stringify(parameters));

    ObjC.schedule(ObjC.mainQueue, () => {
      TMTheme.switchToTheme_(TMTheme.darkTheme());
    });
  },
  dispose() {
    console.log('[dispose]');

    ObjC.schedule(ObjC.mainQueue, () => {
      TMTheme.switchToTheme_(TMTheme.lightTheme());
    });
  }
};
{% endhighlight %}

然后，为了确保此脚本仅加载到该特定应用中，您将创建另一个名为 *twitter.config* 的文件，其中包含：

{% highlight json %}
{
  "filter": {
    "executables": ["Twitter"],
    "bundles": ["com.twitter.twitter-mac"],
    "objc_classes": ["Twitter"]
  }
}
{% endhighlight %}

此示例表示如果满足以下任一条件，我们希望加载脚本：

- 可执行文件名称是 `Twitter`，或者
- 其 bundle 标识符是 `com.twitter.twitter-mac`，或者
- 它加载了一个名为 `Twitter` 的 Objective-C 类。

对于这个特定的例子，您可能只会过滤 bundle ID，因为那是通过最稳定的标识符，如果需要，在代码中进行兼容性检查。

除了 `filter` 键之外，您还可以指定 `parameters` 和 `on_change`，就像上面的 [Script](#script) 配置一样。


[Injected]: /docs/modes/#injected
[insert_dylib]: https://github.com/Tyilo/insert_dylib
[rpc.exports]: /docs/javascript-api/#rpc
[Socket.connect()]: /docs/javascript-api/#socket
