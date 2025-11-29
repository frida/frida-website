---
layout: news_item
title: 'Frida 16.3.0 发布'
date: 2024-05-31 15:43:02 +0200
author: oleavr
version: 16.3.0
categories: [release]
---

此版本包含一些令人兴奋的新事物。让我们直接潜入。

## CoreDevice

从 iOS 17 开始，Apple 转向了一种与 iDevice 端服务通信的新方式，包括他们的 Developer Disk Image (DDI) 服务。他们做事的新方式统一了 Apple 软件与其他 Apple 设备对话的方式，被称为 CoreDevice。它似乎起源于 Apple 推出他们的 T2 协处理器时。Cisco 的 DUO 团队早在 2019 年就对此发表了一些出色的 [research][]。

与 T2 一样，用于 iOS 的新堆栈也使用 RemoteXPC 与服务对话。不过事情稍微复杂一些，因为与 T2 不同，移动设备没有与 macOS 的持久连接，并且还有配对的概念。幸运的是，[@doronz88][] 已经做了一项了不起的工作，逆向并 [documenting][] 了我们需要实现新协议的大部分内容，这为我们节省了大量时间。

即便如此，这也是一项艰巨的任务，但也非常有趣——[@hsorbo][] 和我在结对编程中玩得很开心。涉及相当多的活动部件，让我们快速浏览一下。

插入 iDevice 后，它会公开一个 USB CDC-NCM 网络接口，称为“专用”接口。它还公开了一个用于网络共享的接口，就像过去一样——除了那时它是使用专有的 Apple 协议而不是 CDC-NCM。

这就是我们在尝试从 Linux 主机与其对话时遇到的第一个挑战。首先，iOS 设备需要一个 USB 供应商请求来进行模式切换，以公开新接口。这部分很容易，因为如果我们设置环境变量 `USBMUXD_DEFAULT_DEVICE_MODE` 为 `3`，usbmuxd 守护进程可以为我们做这件事。到目前为止一切顺利。

下一个挑战是 Linux 内核的 CDC-NCM 驱动程序无法绑定到设备。经过一番调试，我们发现这是由于专用网络接口缺少状态端点。状态端点是驱动程序获取有关网络电缆是否插入的通知的方式。Apple 的网络共享网络接口有这样一个端点，这很有意义——如果禁用网络共享，就像电缆被拔掉一样。但是专用接口总是存在的，所以可以理解 Apple 选择不为其包含状态端点。

我们迅速开发了一个 [kernel driver patch][] 来取消对状态端点的要求，这让它工作了。后来我们意识到我们仍然应该要求网络共享接口具有状态端点，所以我们最终进一步完善了我们的补丁。计划是在接下来的几天内提交。

无论如何，随着网络接口的启动，主机端使用 mDNS 来定位 RemoteServiceDiscovery (RSD) 服务正在侦听的 IPv6 地址。主机连接到它并使用 HTTP/2 进行通信，RemoteXPC 消息来回传递。这个特定的服务 RSD 告诉主机专用接口上有哪些服务可用，它们正在侦听的端口号，以及每个服务用于通信的协议等详细信息。

然后，知道哪些服务正在侦听哪些端口，主机查找 Tunnel 服务。此服务允许主机建立到设备的隧道，充当 VPN 以允许其与该隧道内的服务通信。由于建立这样的隧道需要主机和设备之间的配对关系，这意味着隧道内的服务允许主机做比隧道外的服务更多的事情。

基本协议与 RSD 相同，在涉及配对参数二进制 blob 和一些加密技术的来回之后，配对关系被创建或验证。此时两个端点正在使用加密通信，主机要求 Tunnel 服务设置隧道侦听器。

现在，假设主机请求默认传输 QUIC，主机继续连接到它。我们应该注意，Tunnel 服务也支持纯 TCP。据推测，这是为不带 QUIC 堆栈的旧 macOS 版本准备的。另一件值得一提的事情是，Tunnel 服务为主机提供了一个密钥对，因此它将其用作连接设置的一部分。

连接后，设备通过可靠流向主机发送一些数据。数据以 8 字节魔术字“CDTunnel”开头，后跟一个指定其后有效载荷大小的大端 uint16。有效载荷是 JSON，告诉主机主机在隧道内的端点具有哪个 IPv6 地址，以及网络掩码和 MTU。它还告诉主机其自己在隧道内的 IPv6 地址，以及 RSD 服务正在侦听的端口。

然后主机设置一个按刚刚告知的方式配置的 TUN 设备，并开始将从 QUIC 连接接收到的不可靠数据报馈送给它。对于另一个方向的数据，每当有来自 TUN 设备的新数据包时，主机将其馈送到 QUIC 连接中。

所以此时主机连接到隧道内的 RSD 端点，从那里它可以访问设备提供的所有服务。这种新方法的美妙之处在于，与设备端服务通信的客户端不必担心加密，也不必提供配对关系的证明。它们只需在隧道接口上进行纯文本 TCP 连接，QUIC 透明地处理其余部分。

更酷的是，主机可以通过 USB 和 WiFi 建立隧道，并且由于 QUIC 对多路径的本机支持，设备可以在有线和无线之间无缝移动，而不会中断与隧道内服务的连接。

所以，一旦我们实现了所有这些，我们就感到兴奋和乐观。剩下的部分就是做平台集成。呃，是的，那是事情变得更加困难的地方。让我们卡住了一段时间的部分是在 macOS 上，我们意识到我们必须搭载 Apple 现有的隧道。我们发现当已经有一个隧道打开时，Tunnel 服务会拒绝与我们交谈，所以我们不能简单地在 Apple 的隧道旁边打开一个隧道。

虽然我们可以要求用户向 `remoted` 发送 SIGSTOP，允许我们建立自己的隧道，但这不会是一个很好的用户体验。特别是因为任何想要与设备交谈的 Apple 软件都将无法交谈，这使得 Xcode、Console 等变得不那么有用。

没过多久我们就找到了允许我们确定 Apple 隧道内的设备端地址的私有 API，并且还创建了一个所谓的“断言”，以便隧道在我们需要的尽可能长的时间内保持打开状态。但是我们无法弄清楚的部分是如何发现隧道内的设备端 RSD 端口。

我们知道作为本地用户运行的 `remotepairingd` 知道 RSD 端口，但我们找不到让它告诉我们是什么的方法。经过大量的头脑风暴，我们只能想到不切实际的解决方案：

- 端口扫描设备端地址：可能很慢，更快的实现需要 root 权限才能进行原始套接字访问。
- 扫描 `remotepairingd` 的地址空间以查找设备端隧道地址，并定位存储在其附近的端口：启用 SIP 时不起作用。
- 依赖设备端 frida-server 为我们弄清楚事情：这在 jailed iOS 上不起作用，并且会很复杂且可能很脆弱。
- [Grab it from the syslog][]: 可能需要一段时间或需要手动用户操作，并且通过杀死系统守护进程强制重新连接会导致中断。
- 放弃使用隧道，并转移到更高级别的抽象，例如每当我们需要打开服务时使用 MobileDevice.framework：需要我们拥有 entitlements。具体取决于特定的服务。例如，如果我们想与 com.apple.coredevice.appservice 交谈，我们需要 com.apple.private.CoreDevice.canInstallCustomerContent entitlement。但是，试图给自己一个 com.apple.private.* entitlement 是行不通的，因为系统会杀死我们，因为只有 Apple 签名的程序才能使用此类 entitlements。

这是我们决定休息一下并专注于其他事情一段时间的地方，直到我们最终找到一种方法：`remoted` 进程与隧道内的 RSD 服务有一个连接。我们最终得到了一个简单的解决方案，使用 Apple 的 netstat 使用的相同 API：

{% highlight vala %}
foreach (var item in XNU.query_active_tcp_connections ()) {
	if (item.family != IPV6)
		continue;
	if (!item.foreign_address.equal (tunnel_device_address))
		continue;
	if (Darwin.XNU.proc_pidpath (item.effective_pid, path_buf) <= 0)
		continue;
	if (path != "/usr/libexec/remoted")
		continue;

	try {
		var connectable = new InetSocketAddress (tunnel_device_address, item.foreign_port);

		var sc = new SocketClient ();
		SocketConnection connection = yield sc.connect_async (connectable, cancellable);
		Tcp.enable_nodelay (connection.socket);

		return yield DiscoveryService.open (connection, cancellable);
	} catch (GLib.Error e) {
	}
}
{% endhighlight %}

不过，Linux 方面的情况要容易得多，因为我们在那里处于控制之中，可以自己建立隧道。但是有一个挑战：我们不想要求提升的权限才能创建 tun 设备。我们想出的解决方案是使用 [lwIP][] 在用户模式下执行 IPv6。由于我们已经设计了其他构建块以与 GLib.IOStream 一起工作，与套接字和网络分离，我们要做的就是实现一个使用 lwIP 来完成繁重工作的 IOStream。来自 QUIC 连接的数据报被馈送到 lwIP 网络接口，该网络接口发出的数据包作为数据报馈送到 QUIC 连接中。

接下来是 Windows 方面的事情。我们做了一些挖掘，很快意识到 Apple 的软件目前没有建立隧道。官方驱动程序似乎也让 USB 设备保持忙碌，这意味着我们无法轻松触发模式切换并自己做事。拼图的 Windows 部分可能有一个优雅的解决方案，但我们意识到我们已经深陷兔子洞，明智的做法是留待以后解决。所以如果正在阅读本文的任何人有兴趣提供帮助，请务必联系我们。

另一个需要未来改进的领域是我们仅支持 macOS 上的有线连接。一旦我们更新了 frida-server 和 frida-gadget，以便它们在隧道接口出现时侦听它们，这应该很容易改进。

## Jailed iOS 17

随着新的 CoreDevice 基础设施到位，我们还恢复了对 iOS 17 上 jailed 检测的支持。这意味着我们可以再次在最新的 iOS（撰写本文时为 17.5.1）上 spawn（可调试）应用程序。我们仍然存在没有 spawn() 的 attach() 不起作用的问题，因为我们的 jailed 注入器在附加到已经在运行的应用程序时尚不支持可重启的 dyld 情况。这将在未来的版本中解决。

## Device.open_service() 和 Service API

鉴于 Frida 需要讲相当多的协议才能与 Apple 的设备端服务交互，并且应用程序有时也需要其他此类服务，这就提出了一个挑战。应用程序可以自己讲这些协议，例如在使用 Device.open_channel() API 打开到特定服务的 IOStream 之后。但这这意味着它们必须重复实现和维护协议栈的工作，对于像 DTX 这样的协议，它们可能会浪费时间建立 Frida 已经为其自身需求建立的连接。

一种可能的解决方案是将这些服务客户端设为公共 API 并在我们的语言绑定中公开它们。我们还必须为应用程序可能想要与之交谈的所有 Apple 服务实现客户端。这相当多，会导致 Frida API 变得庞大。这也会使 Frida 成为某种大杂烩，这显然不是我们想要前进的方向。

在思考了一段时间后，我想到我们可以提供一个通用的抽象，让应用程序与它们想要的任何服务交谈。所以上周 [@hsorbo][] 和我倒满咖啡就开始着手做这件事。

这是从 Python 与 RemoteXPC 服务交谈是多么容易：

{% highlight py %}
import frida
import pprint

device = frida.get_usb_device()

appservice = device.open_service("xpc:com.apple.coredevice.appservice")
response = appservice.request({
    "CoreDevice.featureIdentifier": "com.apple.coredevice.feature.listprocesses",
    "CoreDevice.action": {},
    "CoreDevice.input": {},
})
pprint.pp(response)
{% endhighlight %}

同样的例子，来自 Node.js：

{% highlight js %}
import frida from 'frida';
import util from 'util';

const device = await frida.getUsbDevice();

const appservice = await device.openService('xpc:com.apple.coredevice.appservice');
const response = await appservice.request({
  'CoreDevice.featureIdentifier': 'com.apple.coredevice.feature.listprocesses',
  'CoreDevice.action': {},
  'CoreDevice.input': {},
});
console.log(util.inspect(response, {
  colors: true,
  depth: Infinity,
  maxArrayLength: Infinity
}));
{% endhighlight %}

结果是：

![open-service-xpc.png](/img/open-service-xpc.png "iOS process list")

既然我们已经看了从 Python 和 Node.js 使用的新 open_service() API，我们可能应该提到从 C 使用此 API（几乎）同样容易：

{% highlight c %}
#include <frida-core.h>

int
main (int argc,
      char * argv[])
{
  GCancellable * cancellable = NULL;
  GError * error = NULL;

  frida_init ();

  FridaDeviceManager * manager = frida_device_manager_new ();

  FridaDevice * device = frida_device_manager_get_device_by_type_sync (manager, FRIDA_DEVICE_TYPE_USB, -1, cancellable, &error);
  FridaService * service = frida_device_open_service_sync (device, "xpc:com.apple.coredevice.appservice", cancellable, &error);

  GVariant * parameters = g_variant_new_parsed ("{"
    "'CoreDevice.featureIdentifier': <'com.apple.coredevice.feature.listprocesses'>,"
    "'CoreDevice.action': <@a{sv} {}>,"
    "'CoreDevice.input': <@a{sv} {}>"
  "}");
  GVariant * response = frida_service_request_sync (service, parameters, cancellable, &error);

  gchar * str = g_variant_print (response, FALSE);
  g_printerr ("%s\n", str);

  return 0;
}
{% endhighlight %}

（为简洁起见省略了错误处理和清理。）

传递给 `open_service()` 的字符串是可以访问服务的地址，它以协议标识符开头，后跟冒号和服务名称。这将返回 Service 接口的实现，如下所示：

{% highlight vala %}
public interface Service : Object {
	public signal void close ();
	public signal void message (Variant message);

	public abstract bool is_closed ();
	public abstract async void activate (Cancellable? cancellable = null) throws Error, IOError;
	public abstract async void cancel (Cancellable? cancellable = null) throws IOError;
	public abstract async Variant request (Variant parameters, Cancellable? cancellable = null) throws Error, IOError;
}
{% endhighlight %}

（为简洁起见省略了同步方法。）

在这里，`request()` 是您使用 Variant 调用的方法，它可以是“任何东西”，字典、数组、字符串等。期望什么取决于特定协议。我们的语言绑定负责将本机值（例如 Python 中的 dict）转换为 Variant。一旦 `request()` 返回，它会为您提供一个带有响应的 Variant。然后将其转换为本机值，例如 Python dict。

对于支持通知的协议，每当收到通知时都会发出 `message` 信号。由于 Frida 的 API 还提供所有方法的同步版本，允许从任意线程调用它们，这提出了一个挑战：如果您在打开特定服务后立即发出消息，您可能来不及注册处理程序。这就是 `activate()` 发挥作用的地方。服务对象开始处于非活动状态，允许注册信号处理程序。然后，一旦您准备好接收事件，您可以调用 `activate()`，或者进行 `request()`，这会将服务对象移至活动状态。

然后，稍后，要关闭事物，可以调用 `cancel()`。`close` 信号对于知道 Service 何时不再可用很有用，例如因为设备被拔掉或者您向其发送了无效消息导致其关闭连接。

与 DTX 服务交谈也很容易，它是 RemoteXPC 的前身，仍被许多 DDI 服务使用。

例如，要抓取屏幕截图：

{% highlight py %}
import frida

device = frida.get_usb_device()

screenshot = device.open_service("dtx:com.apple.instruments.server.services.screenshot")
png = screenshot.request({"method": "takeScreenshot"})
with open("/path/to/outfile.png", "wb") as f:
    f.write(png)
{% endhighlight %}

但这还不是全部。我们还支持与旧式 plist 服务交谈，您发送 plist 作为请求，并接收一个或多个 plist 响应：

{% highlight py %}
import frida

device = frida.get_usb_device()

diag = device.open_service("plist:com.apple.mobile.diagnostics_relay")
diag.request({"type": "query", "payload": {"Request": "Sleep", "WaitForDisconnect": True}})
diag.request({"type": "query", "payload": {"Request": "Goodbye"}})
{% endhighlight %}

正如您可能已经猜到的那样，此示例使连接的 iDevice 进入睡眠状态。

## RPC 二进制传递

使用 Gum 的 JavaScript 绑定的人可能熟悉我们的 RPC API，它使应用程序可以轻松调用其代理上的函数。

此功能的一个长期限制是您无法将二进制数据传递到导出函数中——您必须以某种方式对其进行序列化。这现在终于得到支持。

例如，给定以下代理：

{% highlight js %}
rpc.exports.hello = (name, icon) => {
  console.log(`Name: "${name}"`);
  console.log('Icon:');
  console.log(hexdump(icon, { ansi: true }));
};
{% endhighlight %}

您现在可以像这样从 Python 调用 `hello()`：

{% highlight js %}
script.exports_sync.hello("Joe", b"\x13\x37")
{% endhighlight %}

这将输出：

![rpc-binary-parameter.png](/img/rpc-binary-parameter.png "RPC binary parameter demo")

请注意，只能传递一个二进制参数，并且它必须是最后一个参数。

同一领域的另一个改进是，您现在可以将二进制数据与 JSON 可序列化的 JavaScript 值一起返回。我们以前只支持返回其中之一。这现在也终于得到支持。

例如，给定以下代理：

{% highlight js %}
rpc.exports.peek = name => {
  const module = Process.getModuleByName(name);
  const header = module.base.readByteArray(64);
  return [module, header];
};
{% endhighlight %}

您现在可以像这样从 Python 调用 `peek()`：

{% highlight js %}
module, header = script.exports_sync.peek("libSystem.B.dylib")
print("module:", module)
print("header:", header)
{% endhighlight %}

如果运行在存在 libSystem.B.dylib 的平台上，可能会输出如下内容：

{% highlight sh %}
module: {'name': 'libSystem.B.dylib', 'base': '0x18ec70000', 'size': 8192, 'path': '/usr/lib/libSystem.B.dylib'}
header: b'\xcf\xfa\xed\xfe\x0c\x00\x00\x01\x02\x00\x00\x80\x06\x00\x00\x006\x00\x00\x00\x10\x10\x00\x00\x85\x00\x00\x82\x00\x00\x00\x00\x19\x00\x00\x00(\x02\x00\x00__TEXT\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00@\x0c\x8d\x01\x00\x00\x00'
{% endhighlight %}

## EOF

还有一些其他令人兴奋的更改，所以一定要查看下面的变更日志。

享受吧！

## 变更日志

- 添加 device.open_service(address)，它提供了一个 Service 实现，通过统一接口公开特定于设备的服务。
- fruity: 添加 RemoteXPC 支持，为三个协议 ID 实现了 open_service()：plist, dtx, xpc。
- fruity: 修复 jailed iOS 17 上的 spawn()。
- fruity: 改进 DTX 协议支持。
- python: 添加 open_service() 和 Service API。
- python: 添加对新 RPC 二进制数据传递的支持。
- python: 改进 GVariant 编组支持。
- node: 添加 openService() 和 Service API。
- node: 添加对新 RPC 二进制数据传递的支持。
- node: 改进 GVariant 编组支持。
- exceptor: 在 POSIX 后端添加 SA_ONSTACK 标志。感谢 [@asabil][]！
- gumjs: 支持在 RPC 方法中接收二进制数据。
- gumjs: 支持从 RPC 方法返回数值和二进制数据。
- gumjs: 向 CModule 公开更多 Memory API。感谢 [@hillelpinto][]！
- plist: 修复对写出带有 float 和 double 值的二进制 plist 的支持。

感谢 [@hsorbo][] 在上述所有更改中进行有趣且富有成效的结对编程，没有具体归属！🙌


[research]: https://duo.com/labs/research/apple-t2-xpc
[@doronz88]: https://github.com/doronz88
[documenting]: https://github.com/doronz88/pymobiledevice3/blob/master/misc/RemoteXPC.md
[@hsorbo]: https://twitter.com/hsorbo
[kernel driver patch]: https://lore.kernel.org/all/20231130220109.90734-2-oleavr@frida.re/T/#ma666f28da8f071f3433e915a28b2152d08373de5
[Grab it from the syslog]: https://github.com/doronz88/pymobiledevice3/blob/master/misc/RemoteXPC.md#reusing-the-macos-trusted-tunnel
[lwIP]: https://savannah.nongnu.org/projects/lwip/
[@asabil]: https://twitter.com/asabil
[@hillelpinto]: https://github.com/hillelpinto
