我们投入了大量精力来确保 Frida 能够从桌面一直扩展到嵌入式系统。

虽然我们的预构建二进制文件启用了所有功能，但自己构建 Frida 意味着您可以根据需要对其进行定制并构建明显更小的二进制文件。这是通过调整 `config.mk` 中的可用选项来完成的：

{% highlight make %}
# Features ordered by binary footprint, from largest to smallest
FRIDA_V8 ?= enabled
FRIDA_CONNECTIVITY ?= enabled
FRIDA_DATABASE ?= enabled
FRIDA_JAVA_BRIDGE ?= auto
FRIDA_OBJC_BRIDGE ?= auto
FRIDA_SWIFT_BRIDGE ?= auto
{% endhighlight %}

如果在嵌入式系统上工作，可以禁用所有上述功能。

具体来说，仅在以下情况下才需要它们：
- FRIDA_V8: 默认的 Javascript 运行时是 QuickJS，因此如果不使用它，可以安全地禁用它。如果需要 V8 运行时，例如通过 API `create_script(..., runtime='v8')` 特别请求或通过带有 `--runtime=v8` 的 frida-tools CLI 请求时，则需要它。
- FRIDA_CONNECTIVITY: 如果使用证书启用 TLS，或者使用 `setup_peer_connection()` (API) 或 `--p2p` (CLI)，则需要此项。请注意，网络连接不需要它。例如，像这样使用 frida-server 时不需要它：`frida-server -l 0.0.0.0`。
- FRIDA_DATABASE: 如果使用 [SqliteDatabase](/docs/javascript-api/#sqlitedatabase) 和相关 API，则需要此项，否则可以安全地禁用。
- FRIDA_JAVA_BRIDGE: 当想要在具有 Java 虚拟机或 Android Runtime 环境的进程内调用或插桩 Java API 时需要。请注意，除了 Java 之外，还有其他语言在 JVM 或 Android Runtime 上运行，例如 Kotlin 和 Scala。
- FRIDA_OBJC_BRIDGE 和 FRIDA_SWIFT_BRIDGE: 当想要调用或插桩 Objective-C 或 Swift 代码时需要。在 Apple 操作系统（如 i/macOS）上有用，在 Apple 生态系统之外可以安全地禁用。
 
让我们浏览一下这些，看看不同的选项如何影响 Linux/armhf (32-bit ARM) 上的占用空间大小。

为了使以下内容更清晰一点，我们在 frida-core Meson 选项中添加了 `-Dassets=installed`。这意味着 frida-agent.so 不会嵌入到 frida-server/frida-inject 二进制文件中，而是从文件系统加载。

这也是您在嵌入式系统上通常想要的，因为将代理写出到 /tmp 有点浪费，无论它是由 flash 还是 tmpfs 支持的。

## 在 linux-armhf 上启用所有 config.mk 功能

{% highlight bash %}
3.8M frida-inject
3.2M frida-server
 15M frida-agent.so
 15M frida-gadget.so
{% endhighlight %}

## 步骤 1: 禁用 V8

{% highlight bash %}
3.8M frida-inject
3.2M frida-server
5.2M frida-agent.so
5.3M frida-gadget.so
{% endhighlight %}

Agent 减少了 9.8M。

## 步骤 2: 禁用连接功能（TLS 和 ICE），消除 OpenSSL

{% highlight bash %}
2.6M frida-inject
2.0M frida-server
3.6M frida-agent.so
3.7M frida-gadget.so
{% endhighlight %}

Agent 减少了 1.6M。

## 步骤 3: 禁用 GumJS 数据库 API，消除 SQLite

{% highlight bash %}
2.6M frida-inject
2.0M frida-server
3.2M frida-agent.so
3.3M frida-gadget.so
{% endhighlight %}

Agent 减少了 0.4M。

## 步骤 4: 禁用 GumJS bridges: ObjC, Swift, Java

{% highlight bash %}
2.6M frida-inject
2.0M frida-server
2.8M frida-agent.so
2.9M frida-gadget.so
{% endhighlight %}

Agent 减少了 0.4M。

让我们看看我们剩下了什么：

![frida-agent.so footprint](/img/frida-agent-footprint.png "frida-agent.so footprint")

为了满足我们的好奇心，让我们仔细看看三个突出的组件：

![libcapstone.a footprint](/img/capstone-breakdown.png "libcapstone.a footprint")

![libglib-2.0.a footprint](/img/glib-breakdown.png "libglib-2.0.a footprint")

![libgio-2.0.a footprint](/img/gio-breakdown.png "libgio-2.0.a footprint")
