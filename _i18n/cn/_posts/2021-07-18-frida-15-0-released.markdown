---
layout: news_item
title: 'Frida 15.0 发布'
date: 2021-07-18 00:48:05 +0200
author: oleavr
version: 15.0
categories: [release]
redirect_from: /news/2021/06/16/frida-15-0-released/index.html
---

发生了太多的变化。让我们从指导此版本中大多数其他更改的重大新功能开始：

## Portals

### 第一部分：构想

今年早些时候，[@insitusec][] 和我在集思广益，探讨如何简化分布式检测用例。本质上是发布一个“空心”的 Frida Gadget，其中特定于应用程序的检测由后端提供。

实现此目的的一种方法是使用 Socket.connect() JavaScript API，然后定义特定于应用程序的信令协议，通过该协议加载代码，然后再将其移交给 JavaScript 运行时。

但是这种做事方式很快就会导致相当多的无聊胶水代码，并且像 frida-trace 这样的现有工具实际上无法在这样的设置中使用。

就在那时，@insitusec 建议也许 Frida 的 Gadget 可以提供与其 [Listen][] 交互相反的对应物。因此，它不再是公开 frida-server 兼容接口的服务器，而是可以配置为充当连接到 Portal 的客户端。

然后，这样的 Portal 聚合所有连接的 Gadget，并且还公开了一个 frida-server 兼容接口，所有这些 Gadget 都作为进程出现在其中。在外界看来，它们就像是 Portal 运行所在的同一台机器上的进程：如果您使用 enumerate_processes() 或 frida-ps，它们都有唯一的进程 ID，并且可以无缝地 attach() 到它们。

通过这种方式，现有的 Frida 工具的工作方式完全相同 —— 并且通过在 Portal 上启用 spawn-gating，可以指示任何连接的 Gadget 等待有人在应用所需的检测后 resume() 它。这与其他情况下 spawn-gating 的工作方式相同。

### 第二部分：实现

实现这一点非常有趣，不久之后第一个 PoC 就启动并运行了。不过，花了一些时间才弄清楚所有细节，但这最终 [crystallized][] 为以下内容：

Portal 应公开两个不同的接口：

1. Gadget 可以连接到的 ***cluster*** 接口，允许它们加入集群。
2. 可选地还有一个 ***control*** 接口，控制器可以与之对话。例如 `frida-trace -H my.portal.com -n Twitter -i open`

对于用户来说，这非常简单：只需从我们的 [releases][] 中获取 frida-portal 二进制文件，并在 Gadget 能够 [reach][] 的某台机器上运行它。然后将工具指向它 —— 就像它是一个普通的 frida-server 一样。

但这只是故事的一部分 —— 它将如何用于简单的用例。frida-portal CLI 程序实际上只不过是底层 *PortalService* 的一个瘦 CLI 包装器。这个 CLI 程序只有 [200 lines of code][] 多一点，其中很少是实际逻辑。

也可以使用我们的 frida-core 语言绑定（例如 Python 或 Node.js）来实例化 PortalService。这允许将其配置为不提供任何控制接口，而是访问其 ***device*** 属性。这是一个标准的 Frida Device 对象，可以在其上 enumerate_processes(), attach() 等。或者可以同时做这两件事。

使用 API 还提供了其他功能，但我们将稍后回到这些功能。

### 第三部分：TLS

鉴于在公共互联网上运行 frida-portal 可能非常有用，同样清楚的是我们应该支持 TLS。由于我们已经在其他功能的依赖项中拥有 [glib-networking][]，这使得添加它在足迹方面非常便宜。

在实现方面，[client][] 端只有一点点逻辑，服务器端的故事也同样简单。

对于 CLI 工具，只需传递 `--certificate=/path/to/pem` 即可。如果它是服务器，它需要一个带有公钥 + 私钥的 PEM 编码文件，它将接受来自传入客户端的任何证书。对于客户端，它也期望一个 PEM 编码文件，但只有受信任 CA 的公钥，服务器的证书必须匹配或派生自该公钥。

在 API 级别，归结为：

{% highlight python %}
import frida

manager = frida.get_device_manager()
device = manager.add_remote_device("my.portal.com",
                                   certificate="/path/to/pem/or/inline/pem-data")
session = device.attach("Twitter")
…
{% endhighlight %}

### 第四部分：身份验证

与在公共互联网上运行 frida-portal 密切相关的下一个相当明显的功能是身份验证。在这种情况下，我们的服务器 CLI 程序现在支持 `--token=secret`，我们的 CLI 工具也是如此。

在 API 级别，这也非常简单：

{% highlight python %}
import frida

manager = frida.get_device_manager()
device = manager.add_remote_device("my.portal.com",
                                   token="secret")
session = device.attach("Twitter")
…
{% endhighlight %}

但是，如果您通过 API 实例化 PortalService，这会变得更加有趣，因为它可以轻松插入您自己的自定义身份验证后端：

{% highlight python %}
import frida

def authenticate(token):
    # Where `token` might be an OAuth access token
    # that is used to grab user details from e.g.
    # GitHub, Twitter, etc.
    user = …

    # Attach some application-specific state to the connection.
    return {
        'name': user.name,
    }

cluster_params = frida.EndpointParameters(authentication=('token', "wow-such-secret"))
control_params = frida.EndpointParameters(authentication=('callback', authenticate))
service = frida.PortalService(cluster_params, control_params)
{% endhighlight %}

EndpointParameters 构造函数还支持其他选项，例如 `address`, `port`, `certificate` 等。

### 第五部分：离线模式

这引出了我们的下一个挑战，即如何处理瞬态连接问题。我确实确保在 [PortalClient][] 中实现自动重连逻辑，这就是 Gadget 用于连接到 PortalService 的东西。

但是，即使 Gadget 重新连接到 Portal，在此期间加载的脚本应该发生什么？如果控制器与 Portal 断开连接怎么办？

我们现在有一个处理这两种情况的解决方案。但它是可选的，因此旧行为仍然是默认行为。

它是这样完成的：

{% highlight python %}
session = device.attach("Twitter",
                        persist_timeout=30)
{% endhighlight %}

现在，一旦发生某些连接故障，脚本将保持在远端加载，但发出的任何消息都将排队。在上面的示例中，客户端有 30 秒的时间重新连接，然后脚本被卸载并且数据丢失。

然后控制器将订阅 `Session.detached` 信号以便能够处理这种情况：

{% highlight python %}
def on_detached(reason, crash):
    if reason == 'connection-terminated':
        # Oops. Better call session.resume()

session.on('detached', on_detached)
{% endhighlight %}

一旦 `session.resume()` 成功，任何缓冲的消息都将被传递，生活又变得美好。

上面的示例确实掩盖了一些细节，例如我们当前 Python 绑定挑剔的线程约束，但请查看 [here][] 的完整示例。（一旦我们将 Python 绑定从同步 API 移植到 async/await，这将变得简单得多。）

### 第六部分：延迟和瓶颈

好了，接下来我们在美国的数据中心运行了一个 Portal，但 Gadget 在我朋友在西班牙的家里，而我正试图从挪威使用 frida-trace 控制它。如果来自西班牙的脚本消息必须两次穿越大西洋，那将是一种耻辱，不仅因为延迟，还因为我下个月必须支付的 AWS 账单。因为我现在正在转储内存，那可是相当大的流量。

这有点难，但多亏了 [libnice][]，一个建立在 [GLib][] 之上的轻量级且成熟的 ICE 实现，我们可以继续使用它。鉴于 GLib 已经是我们堆栈的一部分 —— 因为它是我们进行 C 编程的标准库（并且我们的 Vala 代码编译为依赖于 GLib 的 C 代码）—— 这是一个完美的契合。就足迹而言，这是非常好的消息。

作为用户，只需传递 `--p2p` 以及 STUN 服务器即可：

{% highlight sh %}
$ frida-trace \
    -H my.portal.com \
    --p2p \
    --stun-server=my.stunserver.com \
    -n Twitter \
    -i open
{% endhighlight %}

（也支持 TURN 中继。）

API 方面的故事如下所示：

{% highlight python %}
session.setup_peer_connection(stun_server="my.stunserver.com")
{% endhighlight %}

这就是全部内容！

### 第七部分：只有 Gadget 被邀请参加聚会吗？

您可能已经注意到，到目前为止，我们的 Gadget 一直是一个反复出现的主题。我不太热衷于添加仅适用于一种 [mode][] 的功能，例如仅适用于注入模式但不适用于嵌入模式。所以这是我很早就想到的事情，即 Portal 必须是一个普遍可用的功能。

假设我的伙伴正在意大利的客厅里逆向他 iPhone 上的目标，我想加入其中的乐趣，他可以继续运行：

{% highlight sh %}
$ frida-join -U ReversingTarget my.portal.com cert.pem secret
{% endhighlight %}

现在我可以使用 Frida REPL 跳进去：

{% highlight sh %}
$ frida \
    -H my.portal.com \
    --certificate=cert.pem \
    --token=secret \
    --p2p \
    --stun-server=my.stunserver.com \
    -n ReversingTarget
{% endhighlight %}

如果我的伙伴想使用 API 加入 Portal，他可以：

{% highlight python %}
session = frida.get_usb_device().attach("ReversingTarget")
membership = session.join_portal("my.portal.com",
                                 certificate="/path/to/cert.pem",
                                 token="secret")
{% endhighlight %}

### 第八部分：Web

在 Frida 诞生之前，我就一直想构建一个在线协作逆向应用程序。在 Frida 最开始的时候，我构建了一个集成了聊天、控制台等的桌面 GUI。然而，我并不充裕的业余时间是一个挑战，所以我最终摆脱了 GUI 代码并决定专注于 API。

现在我们到了 2021 年，单页应用程序 (SPA) 在许多情况下可能是一个非常有吸引力的选择。我还注意到已经有不少基于 Frida 构建的 SPA，这非常令人兴奋！但是当我独自玩弄 SPA 时，我注意到不得不编写中间件是相当乏味的。

好吧，在 Frida 15 中，我必须进行一些协议更改以适应我目前涵盖的功能，所以这似乎也是真正打破协议并进行主要版本升级的正确时机。这是我很长一段时间以来一直试图避免的事情，因为我知道它们对每个人（包括我自己）来说是多么痛苦。

所以现在浏览器终于可以加入其中的乐趣，而无需任何中间件：

{% highlight js %}
async function start() {
  const ws = wrapEventStream(new WebSocket(`ws://${location.host}/ws`));
  const bus = dbus.peerBus(ws, {
    authMethods: [],
  });

  const hostSessionObj = await bus.getProxyObject('re.frida.HostSession15',
      '/re/frida/HostSession');
  const hostSession = hostSessionObj.getInterface('re.frida.HostSession15');

  const processes: HostProcessInfo[] = await hostSession.enumerateProcesses({});
  console.log('Got processes:', processes);

  const target = processes.find(([, name]) => name === 'hello2');
  if (target === undefined) {
    throw new Error('Target process not found');
  }
  const [pid] = target;
  console.log('Got PID:', pid);

  const sessionId = await hostSession.attach(pid, {
    'persist-timeout': new Variant('u', 30)
  });
  …
}
{% endhighlight %}

（完整示例可以在 [examples/web_client][] 中找到。）

这意味着 Frida 的网络协议现在是基于 WebSocket 的，因此浏览器终于可以直接与正在运行的 Portal/frida-server 对话，而无需中间有任何中间件或网关。

但我不想这只是一个半生不熟的故事，所以我确保 [peer-to-peer implementation][] 建立在 WebRTC 数据通道上 —— 这样即使是浏览器也可以以最小的延迟进行通信，并有助于保持较低的 AWS 账单。

### 第九部分：资产

一旦我们构建了一个与我们的 Portal 配套的 Web 应用程序，它是原生讲 WebSocket 的，因此也是 HTTP，我们也可以让从同一台服务器为该 SPA 提供服务变得超级容易：

{% highlight sh %}
$ ./frida-portal --asset-root=/path/to/web/app
{% endhighlight %}

这在 API 级别也很容易：

{% highlight python %}
control_params = frida.EndpointParameters(asset_root="/path/to/web/app")
service = frida.PortalService(cluster_params, control_params)
{% endhighlight %}

### 第十部分：协作

一旦我们有了一个控制器，比如说一个 Web 应用程序，自然的下一步就是我们可能想要协作功能，其中该 SPA 的多个运行实例能够相互通信。

鉴于我们在控制器和 PortalService 之间已经有了 TCP 连接，让开发人员使用该通道实际上是免费的。对于许多用例，需要额外的信令通道会带来很多可以避免的复杂性。

这就是新的 `Bus` API 发挥作用的地方：

{% highlight python %}
import frida

def on_message(message, data):
    # TODO: Handle incoming message.
    pass

manager = frida.get_device_manager()
device = manager.add_remote_device("my.portal.com")
bus = device.bus

bus.on('message', on_message)
bus.attach()

bus.post({
    'type': 'rename',
    'address': "0x1234",
    'name': "EncryptPacket"
})
bus.post({
    'type': 'chat',
    'text': "Hey, check out EncryptPacket everybody"
})
{% endhighlight %}

在这里，我们首先附加一个消息处理程序，以便我们可以从 Portal 接收消息。

然后我们调用 `attach()` 以便 Portal 知道我们有兴趣与它通信。（我们不希望它向不使用 Bus 的控制器发送消息，例如 frida-trace。）

最后，我们 `post()` 两种不同的消息类型。由 PortalService 决定如何处理它们。

所以这意味着远程 PortalService 需要通过 API 实例化，因为传入的消息需要被处理 —— Portal 不会自己将它们转发给其他控制器。

不过不用担心，这很容易：

{% highlight python %}
import frida
import sys

def on_message(connection_id, message, data):
    # TODO: Handle incoming message.
    pass

cluster_params = frida.EndpointParameters()
control_params = frida.EndpointParameters()
service = frida.PortalService(cluster_params, control_params)
service.on('message', on_message)
service.start()

sys.stdin.read()
{% endhighlight %}

在 `on_message()` 中，它应该查看 `message` 并决定做什么。

它可能会选择回复发送消息的控制器：

{% highlight python %}
service.post(connection_id, {
    'type': 'rename-rejected',
    'reason': "Not authorized"
})
{% endhighlight %}

另一件有用的事情是每当有人在其 Bus 对象上调用 attach() 时发送欢迎消息：

{% highlight python %}
def on_subscribe(connection_id):
    service.post(connection_id, {
        'type': 'welcome',
        'users': [user.nick for user in connected_users]
    })

service.on('subscribe', on_subscribe)
{% endhighlight %}

根据您的应用程序，您可能还需要一种方法向所有连接到其 Bus 的控制器广播消息：

{% highlight python %}
service.broadcast({
    'type': 'announce',
    'text': "Important Service Announcement"
})
{% endhighlight %}

您还可以向控制器子集 `narrowcast()` 消息：

{% highlight python %}
service.narrowcast("#reversing", {
    'type': 'chat',
    'sender': user.nick,
    'text': "Hello everyone"
})
{% endhighlight %}

这意味着任何标记为 `#reversing` 的控制器连接都将收到该消息。标记是这样完成的：

{% highlight python %}
service.tag(connection_id, "#reversing")
{% endhighlight %}

此类标签可以基于操作添加，例如控制器发送“join”消息以加入频道。它们也可以基于身份验证应用，以便只有属于某个 GitHub 组织的连接才会收到该消息 —— 仅举一例。

最后，在集群方面，加入 Portal 时还可以指定访问控制列表 (ACL)。ACL 是一个字符串数组，指定标签，这些标签将授予控制器发现给定进程并与之交互的权限。这意味着需要为每个应被授予访问某个节点/节点组权限的控制器使用 `service.tag()`。

这几乎就是全部内容。有关更全面的示例，请查看 [examples/portal_server.py][] 和 [examples/portal_client.py][]，它们实现了类似 IRC 的聊天服务。

## 系统参数

早在 5 月，我与 [@Hexploitable][] 聊过，他正在开发一个工具，他需要根据设备运行的是 iOS 还是 Android 来选择 Device 对象。这是一个过去曾被请求过的功能，感觉是时候最终解决它了。

虽然可以执行 device.attach(0) 并在系统会话中加载脚本，以便在 Frida 本身内部运行代码（例如在远程 frida-server 中），但这有点乏味。如果 Device 代表受限/非 root 设备，这也行不通，因为在那里的代码执行受到更多限制。

所以在集思广益之后，@Hexploitable 开始致力于实现它，并很快达到了第一个草案工作的地步。这后来由我进行了改进，并在 Portals 功能最终落地后不久合并。

API 很简单，并且将来很容易扩展：

{% highlight sh %}
$ python3 -c 'import frida; import json; \
    print(json.dumps(frida.query_system_parameters()))' \
    | jq
{% endhighlight %}

![macOS Device](/img/query-system-parameters-macos.png "Output for a macOS Device")

如果我连接一个受限的 iOS 设备，我也可以查询它：

{% highlight sh %}
$ python3 -c 'import frida; import json; \
    device = frida.get_usb_device(); \
    print(json.dumps(device.query_system_parameters()))' \
    | jq
{% endhighlight %}

![iOS Device](/img/query-system-parameters-ios.png "Output for an iOS Device")

这里要注意的一个重要细节是 `access: 'jailed'`。这就是您如何确定您是否通过我们对受限 iOS/Android 系统的支持（即仅限于可调试的应用程序）访问设备，还是实际与远程 frida-server 对话 —— 这就是 `access: 'full'` 的意思。

对于 Android 来说，事情还没有那么丰富（顺便说一句，欢迎 PR！），但仍然有很多有用的细节：

![Android Device](/img/query-system-parameters-android.png "Output for an Android Device")

如果是符合 LSB 的发行版，我们还可以识别特定的 Linux 发行版：

![Ubuntu Device](/img/query-system-parameters-ubuntu.png "Output for an Ubuntu Device")

最后但并非最不重要的一点是 Windows：

![Windows Device](/img/query-system-parameters-windows.png "Output for a Windows Device")

## 应用程序和进程参数

另一个很酷的想法是在一些即兴聊天后开始形成的，当时 [@pancake][] 告诉我，知道已安装 iOS 应用程序的特定版本会很有用。

由于我在开发 Portals 功能时已经在很多方面破坏了协议，这似乎也是打破它更多并避免以后再次痛苦的主要版本升级的好时机。

快进一点，结果如下：我们的 `Application` 和 `Process` 对象不再有任何 `small_icon` 或 `large_icon` 属性，但它们现在有一个 `parameters` 字典。

默认情况下，使用 `enumerate_applications()`，事情看起来很熟悉：

![enumerate_applications()](/img/enumerate-applications-ios-minimal.png "enumerate_applications()")

但是通过将其更改为 `enumerate_applications(scope='metadata')`，事情变得更加有趣：

![enumerate_applications(scope='metadata')](/img/enumerate-applications-ios-metadata.png "enumerate_applications(scope='metadata')")

在这里我们可以看到 iOS Twitter 应用程序的版本和构建号，其应用程序包在文件系统上的位置，它拥有的容器，它是当前最前端的应用程序，它启动了多久等。

我们还可以将其调高到 `enumerate_applications(scope='full')` 并获取图标：

![enumerate_applications(scope='full')](/img/enumerate-applications-ios-full.png "enumerate_applications(scope='full')")

如果 query_system_parameters() 报告 `access: 'jailed'`，则 `debuggable: true` 参数非常有用，因为这意味着您的应用程序可能希望过滤应用程序列表以仅显示它能够 spawn() 和/或 attach() 的应用程序，或者可能更突出地显示可调试应用程序以提供更好的用户体验。

可能还值得一提的是，`get_frontmost_application()` 现在也支持传递 `scope`。

熟悉旧 API 的人可能已经注意到，图标现在可能以压缩形式作为 PNG 交付。以前这总是未压缩的 RGBA 数据，iOS 端会进行 PNG 解码并缩小到两个固定分辨率（16x16 和 32x32）。

所有这些意味着我们会浪费大量的 CPU 时间、内存和带宽来包含图标，即使所有数据最终都会进入不使用它的 CLI 工具。所以现在有了 Frida 15，您可能会注意到应用程序和进程列表速度要快得多。即使您确实请求图标，它也应该比以前更快，因为我们不进行任何解压缩和缩小。

那是应用程序列表。以上所有内容也适用于进程列表，这就是 `enumerate_applications(scope='full')` 现在可能的样子：

![enumerate_processes(scope='full')](/img/enumerate-processes-ios-full.png "enumerate_processes(scope='full')")

在这里也很清楚，Twitter 应用程序当前是最前端的，其父 PID 是 launchd (PID 1)，它作为哪个用户运行，何时启动等。

您可能想知道为什么 `applications` 是一个数组，答案可能最好用 Android 的一个例子来说明：

![enumerate_processes(scope='full')](/img/enumerate-processes-android-full.png "enumerate_processes(scope='full')")

“com.android.phone” 进程实际上托管了六个不同的“应用程序”！

再一次，最后但并非最不重要的一点是，我没有忘记 Windows：

![enumerate_processes(scope='full')](/img/enumerate-processes-windows-full.png "enumerate_processes(scope='full')")

这就是“scope”选项。还有另一个，用于 UI。这个想法是，UI 可能希望快速获取应用程序/进程列表，并且在用户与特定条目交互或将条目子集滚动到视图中之前，实际上可能不需要元数据/图标。因此，我们现在提供一个选项来支持此类用例。

假设我们只想获取两个特定应用程序的元数据，我们现在可以这样做：

{% highlight python %}
ids = [
    "com.atebits.Tweetie2",
    "no.sparebank1.mobilbank"
]
apps = device.enumerate_applications(identifiers=ids,
                                     scope='full')
{% endhighlight %}

![enumerate_applications(identifiers=x)](/img/enumerate-selected-applications.png "enumerate_applications(identifiers=x)")

我们也支持进程列表的相同功能，如下所示：

{% highlight python %}
processes = device.enumerate_processes(pids=[1337, 1338],
                                       scope='full')
{% endhighlight %}

## Portals 和应用程序/进程参数

现在我们已经涵盖了应用程序参数 **和** portals，有一个重要的细节值得一提：鉴于在 PortalService 的情况下实现 query_system_parameters() 没有多大意义，因为它正在从任意数量的（可能是远程的）系统浮现进程，我们可以使用应用程序/进程参数来填补这一空白。

这意味着来自 PortalService 的任何 Application 和 Process，如果 `scope` 设置为 `metadata` 或 `full`，将提供一个名为 `system` 的参数，其中包含该特定应用程序/进程的系统参数。这样应用程序仍然可以提前知道它是否对特定进程感兴趣。

## 受限 iOS 和 Android 改进

我在实现应用程序和进程参数功能时玩得很开心，并试图看看我能把受限（非 root）和越狱（root）之间的差距缩小到多大。例如在 Android 上，我们在非 root 代码路径中甚至没有获取应用程序标签。这是因为我们依赖于通过 ADB 运行 shell 命令，而在这种情况下我找不到获取标签的方法。

shell 命令路线非常脆弱，因为大多数工具以供人类使用而不是机器使用的格式输出详细信息。显然，随着 Android 的发展，这种输出可能会发生变化。

因此，我们现在有一个微小的预构建 .dex，我们将其复制并运行，获取元数据只是向该辅助进程进行 RPC 调用的问题。这意味着我们能够为非 root 提供与我们在 root 情况下提供的所有相同的详细信息，在 root 情况下我们在 Android 端运行 frida-server。

另一件值得一提的事情是，我们不再将 Android 的启动器视为最前端的应用程序，这意味着这现在与我们在 iOS 上的行为一致，其中 SpringBoard 从不被视为最前端的应用程序。

作为这些重大更改的一部分，我还添加了在 Android 上获取图标的代码，包括非 root 和 root，因此此功能不再仅限于 iOS、macOS 和 Windows。

我们没有为受限 iOS 提供图标，但那个功能差距现在也已弥合。然而，受限和越狱 iOS 之间仍然存在一个区别：`ppid` 和 `user` 参数在受限情况下不可用，因为这没有被我目前知道的任何 lockdown/DTX API 公开。但除此之外，情况相当不错。

## i/macOS 上大幅改进的回溯

感谢 [@hot3eed][] 提出的非常令人兴奋的拉取请求，我们现在有了一个使用 Objective-C 运行时的 i/macOS 符号化回退。通过这种方式，我们可能能够将其解析为 Objective-C 方法，而不是显示 `module!0x1234`。耶！

我们还得到了 [@mrmacete][] 的另一个很棒的贡献，其中 NativeCallback 现在总是公开一个上下文，所以你可以做 `Thread.backtrace(this.context)` 并期望它在所有情况下都能工作。

这以前只有在 NativeCallback 用作 Interceptor 替换时才可能。因此，如果您使用 ObjC.implement() 来 swizzle Objective-C API，您实际上无法从该 NativeCallback 捕获回溯。所以这是一个超级令人兴奋的改进！

## Android 上未提取的本机库

对于那些在 Android 上使用 Frida 的人，您可能遇到过本机库不驻留在文件系统上，而是直接从应用程序的 .apk 加载的应用程序。感谢 [@P-Sc][] 的巨大贡献，我们现在透明地支持这一点 —— 不需要更改您现有的检测代码。

## 升级的操作系统支持

我们现在还支持 macOS Monterey、iOS 15 和 Android 12 的最新测试版。特别感谢 [Corellium][] 的 [@alexhude][] 帮助调试和测试 iOS 15 上的东西，以及 [@pengzhangdev][] 贡献了一个修复 frida-java-bridge 以支持 Android 12。

## 联网 iOS 设备

另一个被多次请求的功能是支持联网 iOS 设备。如果您不想通过整天插着电源来破坏 iPhone/iPad 的电池，这非常棒。这个功能最棒的地方在于它“就是好用” —— 如果您运行 `frida-ls-devices`，您应该能看到它们。

值得一提的只有两个陷阱：您现在可能拥有两个具有相同 ID 的不同 Device 对象，以防联网 iOS 设备在通过网络可达的同时也已插入。

例如：

{% highlight sh %}
$ frida-ls-devices
Id                         Type    Name
-------------------------  ------  -------------------------------------
local                      local   Local System
00008027-xxxxxxxxxxxxxxxx  usb     iPad
socket                     remote  Local Socket
00008027-xxxxxxxxxxxxxxxx  remote  iOS Device [fe80::146f:75af:d79:630c]
{% endhighlight %}

因此，如果您使用 `-U` 或 `frida.get_usb_device()`，事情将像以前一样工作，您将通过 USB 使用您的设备。但是，如果您想使用联网设备，那么通过 ID 解析意味着 USB 条目将优先，因为它通常在设备列表中位于联网设备之前。

这意味着您还需要检查它的 `type`。我们的 CLI 工具尚未提供开关来执行此操作，但如果有人感兴趣，这将是一个受欢迎的拉取请求！

第二个陷阱是 frida-server 默认只监听环回接口，这意味着我们将无法通过网络连接到它。因此，如果您手动或通过 Cydia 使用我们的 iOS .deb，您将不得不编辑 `/Library/LaunchDaemons/re.frida.server.plist` 以添加 `--listen` 开关，然后使用 `launchctl` 重启它。

这也可能是您想要利用前面提到的新 TLS 和身份验证功能的情况，具体取决于您对网络环境的信任程度。

## EOF

还有很多其他令人兴奋的更改，所以一定要查看下面的变更日志。

享受吧！


### 15.0.0 中的变化

- 引入 PortalService API 和守护进程，这是一个网络服务，用于编排由 Frida 检测的远程进程集群。实现 frida-server 兼容的控制接口，以及目标进程中的 agent 和 gadget 可以与之对话的集群接口。连接的控制器可以枚举进程，就像它们在运行 portal 的系统本地一样，并且能够 attach() 并启用 spawn-gating 以应用早期插桩。
- 添加 Session.join_portal()，使与远程 PortalService 共享进程控制变得容易，与其他节点一起加入其集群。
- 向 frida-gadget 添加“connect”交互，以便它也可以加入 PortalService 集群。
- 添加 PortalClient，用于实现 Session.join_portal() 和 frida-gadget 的“connect”交互。连接到 PortalService 并加入其集群。在瞬态故障的情况下实现自动重连。还支持指定 ACL，这是 PortalService 必须要求连接的控制器至少拥有其中之一的标签列表。由应用程序根据例如身份验证来实现控制器的标记。
- 添加 Device.bus API 以允许连接到 PortalService 的客户端与其交换特定于应用程序的消息。需要使用 API 实例化服务以连接消息处理程序和协议逻辑。
- 添加 Session 持久性支持，通过在 attach() 到进程时指定非零“persist_timeout”选项来启用。当服务器随后检测到拥有会话的客户端断开连接时，它将允许脚本保持加载状态，直到达到超时（以秒为单位）。在此期间发出的任何脚本和调试器消息都将排队，如果客户端在达到超时之前返回，则稍后可能会传递这些消息。
- 添加 TLS 支持，通过指定证书启用。在服务器端，这是一个带有公钥和私钥的 PEM，服务器将接受来自客户端的任何证书。但是对于客户端，这是一个带有受信任 CA 公钥的 PEM，服务器的证书必须匹配或派生自该公钥。
- 添加身份验证支持，通过指定令牌启用。守护进程允许通过 CLI 选项指定静态令牌，API 允许插入自定义身份验证后端 —— 这意味着可以根据需要解释令牌。
- 将网络协议移动到 WebSocket。
- 添加协议级 keepalive。
- 实现 WebRTC 数据通道兼容的点对点支持，通过在 Session 上调用 setup_peer_connection() 启用。这允许直接连接。


[@insitusec]: https://twitter.com/insitusec
[Listen]: /docs/gadget/#listen
[crystallized]: https://twitter.com/oleavr/status/1393339683936608259
[releases]: https://github.com/frida/frida/releases
[reach]: https://twitter.com/oleavr/status/1393666016793268228
[200 lines of code]: https://github.com/frida/frida-core/blob/15.0.0/src/portal.vala#L1-L224
[glib-networking]: https://gitlab.gnome.org/GNOME/glib-networking
[client]: https://github.com/frida/frida-core/blob/15.0.0/src/socket/service.vala#L15-L27
[PortalClient]: https://github.com/frida/frida-core/blob/15.0.0/src/portal-client.vala
[here]: https://github.com/frida/frida-python/blob/15.0.0/examples/portal_client.py#L42-L61
[libnice]: https://libnice.freedesktop.org/
[GLib]: https://gitlab.gnome.org/GNOME/glib
[mode]: /docs/modes/
[examples/web_client]: https://github.com/frida/frida-core/tree/15.0.0/examples/web_client
[peer-to-peer implementation]: https://github.com/frida/frida-core/blob/15.0.0/src/socket/p2p-broker.vala
[examples/portal_server.py]: https://github.com/frida/frida-python/blob/15.0.0/examples/portal_server.py
[examples/portal_client.py]: https://github.com/frida/frida-python/blob/15.0.0/examples/portal_client.py
[@Hexploitable]: https://twitter.com/Hexploitable
[@pancake]: https://twitter.com/trufae
[@hot3eed]: https://github.com/hot3eed
[@mrmacete]: https://twitter.com/bezjaje
[@P-Sc]: https://github.com/P-Sc
[@alexhude]: https://twitter.com/alexhude
[Corellium]: https://www.corellium.com/
[@pengzhangdev]: https://github.com/pengzhangdev
