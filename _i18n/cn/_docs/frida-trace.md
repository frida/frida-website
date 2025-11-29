frida-trace 是一个用于动态跟踪函数调用的工具。

{% highlight bash %}
# 跟踪 Safari 中的 recv* 和 send* API，在日志中插入库名称
$ frida-trace --decorate -i "recv*" -i "send*" Safari

# 跟踪 Safari 中的 ObjC 方法调用
$ frida-trace -m "-[NSView drawRect:]" Safari

# 在 iPhone 上启动 SnapChat 并跟踪加密 API 调用
$ frida-trace \
    -U \
    -f com.toyopagroup.picaboo \
    -I "libcommonCrypto*"

# 在 Android 设备上启动 YouTube 并跟踪签名中带有 “certificate” 的 Java 方法 (s)，忽略大小写 (i)
# 并且仅在用户定义的类中搜索 (u)
$ frida-trace \
    -U \
    -f com.google.android.youtube \
    --runtime=v8 \
    -j '*!*certificate*/isu'

# 跟踪 Android 上 Samsung FaceService 应用中的所有 JNI 函数
$ frida-trace -U -i "Java_*" com.samsung.faceservice

# 跟踪 Windows 进程对 msvcrt.dll 中 "mem*" 函数的调用
$ frida-trace -p 1372 -i "msvcrt.dll!*mem*"

# 跟踪进程中匹配 "*open*" 的所有函数，msvcrt.dll 中的除外
$ frida-trace -p 1372 -i "*open*" -x "msvcrt.dll!*open*"

# 跟踪 libjpeg.so 中的未导出函数
$ frida-trace -p 1372 -a "libjpeg.so!0x4793c"
{% endhighlight %}

## 选项完整列表

{% highlight bash %}
$ frida-trace -h
usage: frida-trace [options] target

positional arguments:
  args                  额外参数和/或目标

options:
  -h, --help            显示此帮助信息并退出
  -D ID, --device ID    连接到具有给定 ID 的设备
  -U, --usb             连接到 USB 设备
  -R, --remote          连接到远程 frida-server
  -H HOST, --host HOST  连接到 HOST 上的远程 frida-server
  --certificate CERTIFICATE
                        与 HOST 进行 TLS 通信，期望 CERTIFICATE
  --origin ORIGIN       连接到远程服务器，设置 “Origin” 标头为 ORIGIN
  --token TOKEN         使用 TOKEN 向 HOST 进行身份验证
  --keepalive-interval INTERVAL
                        设置保活间隔（秒），或 0 以禁用（默认为 -1 以根据传输自动选择）
  --p2p                 与目标建立点对点连接
  --stun-server ADDRESS
                        设置用于 --p2p 的 STUN 服务器 ADDRESS
  --relay address,username,password,turn-{udp,tcp,tls}
                        添加用于 --p2p 的中继
  -f TARGET, --file TARGET
                        启动 FILE
  -F, --attach-frontmost
                        附加到最前端的应用程序
  -n NAME, --attach-name NAME
                        附加到 NAME
  -N IDENTIFIER, --attach-identifier IDENTIFIER
                        附加到 IDENTIFIER
  -p PID, --attach-pid PID
                        附加到 PID
  -W PATTERN, --await PATTERN
                        等待匹配 PATTERN 的启动
  --stdio {inherit,pipe}
                        启动时的 stdio 行为（默认为 “inherit”）
  --aux option          启动时设置辅助选项，例如 “uid=(int)42”（支持的类型有：string, bool, int）
  --realm {native,emulated}
                        附加的领域
  --runtime {qjs,v8}    要使用的脚本运行时
  --debug               启用 Node.js 兼容的脚本调试器
  --squelch-crash       如果启用，将不会向控制台转储崩溃报告
  -O FILE, --options-file FILE
                        包含额外命令行选项的文本文件
  --version             显示程序的版本号并退出
  -I MODULE, --include-module MODULE
                        包含 MODULE
  -X MODULE, --exclude-module MODULE
                        排除 MODULE
  -i FUNCTION, --include FUNCTION
                        包含 [MODULE!]FUNCTION
  -x FUNCTION, --exclude FUNCTION
                        排除 [MODULE!]FUNCTION
  -a MODULE!OFFSET, --add MODULE!OFFSET
                        添加 MODULE!OFFSET
  -T INCLUDE_IMPORTS, --include-imports INCLUDE_IMPORTS
                        包含程序的导入
  -t MODULE, --include-module-imports MODULE
                        包含 MODULE 导入
  -m OBJC_METHOD, --include-objc-method OBJC_METHOD
                        包含 OBJC_METHOD
  -M OBJC_METHOD, --exclude-objc-method OBJC_METHOD
                        排除 OBJC_METHOD
  -y SWIFT_FUNC, --include-swift-func SWIFT_FUNC
                        包含 SWIFT_FUNC
  -Y SWIFT_FUNC, --exclude-swift-func SWIFT_FUNC
                        排除 SWIFT_FUNC
  -j JAVA_METHOD, --include-java-method JAVA_METHOD
                        包含 JAVA_METHOD
  -J JAVA_METHOD, --exclude-java-method JAVA_METHOD
                        排除 JAVA_METHOD
  -s DEBUG_SYMBOL, --include-debug-symbol DEBUG_SYMBOL
                        包含 DEBUG_SYMBOL
  -q, --quiet           不格式化输出消息
  -d, --decorate        将模块名称添加到生成的 onEnter 日志语句
  -S PATH, --init-session PATH
                        用于初始化会话的 JavaScript 文件的路径
  -P PARAMETERS_JSON, --parameters PARAMETERS_JSON
                        JSON 格式的参数，作为名为 'parameters' 的全局变量公开
  -o OUTPUT, --output OUTPUT
                        将消息转储到文件
  --ui-port UI_PORT     提供 UI 的 TCP 端口

{% endhighlight %}

## -U, --usb: 连接到 USB 设备

此选项告诉 `frida-trace` 在通过主机 USB 连接连接的远程设备上执行跟踪。

示例：您想从主机 Windows 机器跟踪 Android 设备上运行的应用程序。如果您指定 `-U / --usb`，frida-trace 将执行必要的工作，以便与远程设备传输所有数据并相应地进行跟踪。

<div class="note">
  <h5>将 frida-server 二进制文件复制到远程设备</h5>
  <p>在跟踪远程设备时，请记住将 <a href="https://github.com/frida/frida/releases">适合平台的 frida-server 二进制文件</a> 复制到远程设备。复制后，请务必在开始跟踪会话之前运行 frida-server 二进制文件。</p>
  <p>例如，要跟踪远程 Android 应用程序，您可以将 'frida-server-12.8.0-android-arm' 二进制文件复制到 Android 的 /data/local/tmp 文件夹。使用 adb shell，您可以在后台运行服务器（例如 "frida-server-12.8.0-android-arm &"）。</p>
</div>

## -O: 通过文本文件传递命令行选项

使用此选项，您可以通过一个或多个文本文件传递任意数量的命令行选项。文本文件中的选项可以在一行或多行上，每行任意数量的选项，包括其他 `-O` 命令选项。

此功能对于处理大量命令行选项非常有用，并解决了命令行超过操作系统最大命令行长度的问题。

例如：

{% highlight console %}
$ frida-trace -p 9753 --decorate -O additional-options.txt
{% endhighlight %}

其中 additional-options.txt 是：

{% highlight console %}
-i "gdi32full.dll!ExtTextOutW"
-S core.js -S ms-windows.js
-O module-offset-options.txt
{% endhighlight %}

而 module-offset-options.txt 是：

{% highlight console %}
-a "gdi32full.dll!0x3918DC" -a "gdi32full.dll!0xBE7458"
-a "gdi32full.dll!0xBF9904"
{% endhighlight %}

## -I, -X: 包含/排除模块

这些选项允许您在一个选项中包含或排除特定模块（例如 *.so, *.dll）中的 **所有** 函数。该选项期望一个文件名 glob 来匹配一个或多个模块。任何匹配 glob 模式的模块都将被完整地包含或排除。

`frida-trace` 将为 `-I` 选项匹配的每个函数生成一个 JavaScript 处理程序文件。

要在包含整个模块后排除特定函数，请参阅 `-x` 选项。

## -i, -x: 包含/排除函数（基于 glob）

这些选项使您能够根据需要包含或排除匹配的函数。这些是灵活的选项，允许从 **所有** 模块中的 **所有** 函数到特定模块中的单个函数的粒度范围。

`frida-trace` 将为 `-i` 选项匹配的每个函数生成一个 JavaScript 处理程序文件。

`-i / -x` 选项在语法上与其大写对应项不同，因为它们接受以下任何形式（MODULE 和 FUNCTION 都是 glob 模式）：

<pre style="font-family: monospace;">
- MODULE!FUNCTION
- FUNCTION
- !FUNCTION
- MODULE!
</pre>

以下是一些示例及其说明：

| 选项值 | 说明 |
| --------------------- | ---------------------------------------------------------------- |
| -i "msvcrt.dll!*cpy*" | 匹配名称中带有 'cpy' 的所有函数，仅在 msvcrt.dll 中 |
| -i "*free*"           | 匹配所有模块中名称中带有 'free' 的所有函数 |
| -i "!*free*"          | 与 -i "*free*" 相同 |
| -i "gdi32.dll!"       | 跟踪 gdi32.dll 中的所有函数（与 -I "gdi32.dll" 相同） |

<div class="note info">
  <h5>frida-trace 的工作集以及包含和排除的顺序</h5>
  <p>frida-trace 有一个“工作集”的内部概念，即一组“模块:函数”对，其处理程序将在运行时被跟踪。工作集的内容可以通过包含/排除命令行选项 (-I / -X / -i / -x) 进行更改。</p>
  <p>重要的是要理解包含/排除选项的顺序很重要。每个此类选项都在工作集的当前状态上工作，不同的选项顺序可能导致不同的结果。换句话说，包含/排除选项是过程性的（即顺序很重要），而不仅仅是声明性的。</p>
  <p>例如，假设我们要跟踪正在运行的进程中所有模块中的所有 "str*" 和 "mem*" 函数。在我们的示例中，这些函数位于三个模块中：<i>ucrtbase.dll, ntdll.dll, 和 msvcrt.dll</i>。然而，为了减少噪音，我们不想跟踪在 msvcrt.dll 模块中找到的任何函数。</p>
  <p>我们将描述命令行上的三种不同选项顺序，并表明它们产生不同的结果。</p>
  <ul>
    <li><div style="font-family: monospace">-i "str*" -i "mem*" -X "msvcrt.dll"
        </div></li>
      <ul>
        <li><div style="font-family: monospace">'-i "str*"'</div> 匹配 3 个模块中的 80 个函数，工作集有 80 个条目</li>
        <li><div style="font-family: monospace">'-i "mem*"'</div> 匹配 3 个模块中的 18 个函数，工作集有 98 个条目</li>
        <li><div style="font-family: monospace">'-X "msvcrt.dll"'</div> 移除源自 msvcrt.dll 的 28 个 "str" 和 6 个 "mem" 函数，<b>最终工作集有 64 个条目</b>。</li>
      </ul>
    <li><div style="font-family: monospace">-i "str*" -X "msvcrt.dll" -i "mem*"
        </div></li>
      <ul>
        <li><div style="font-family: monospace">'-i "str*"'</div> 匹配 3 个模块中的 80 个函数，工作集有 80 个条目</li>
        <li><div style="font-family: monospace">'-X "msvcrt.dll"'</div> 移除源自 msvcrt.dll 的 28 个 "str" 函数，工作集有 52 个条目。</li>
        <li><div style="font-family: monospace">'-i "mem*"'</div> 匹配 3 个模块（包括 msvcrt.dll）中的 18 个函数，<b>最终工作集有 70 个条目</b></li>
      </ul>
    <li><div style="font-family: monospace">-X "msvcrt.dll" -i "str*" -i "mem*"
        </div></li>
      <ul>
        <li><div style="font-family: monospace">'-X "msvcrt.dll"'</div> 尝试移除源自 msvcrt.dll 的 28 个 "str" 和 6 个 "mem" 函数。由于工作集为空，因此没有要移除的内容，工作集有 0 个条目。</li>
        <li><div style="font-family: monospace">'-i "str*"'</div> 匹配 3 个模块中的 80 个函数，工作集有 80 个条目</li>
        <li><div style="font-family: monospace">'-i "mem*"'</div> 匹配 3 个模块中的 18 个函数，<b>最终工作集有 98 个条目</b></li>
      </ul>
  </ul>
</div>

## -a: 包含函数（基于偏移量）

此选项允许跟踪其名称未由其父模块导出的函数（例如，静态 C/C++ 函数）。只要您知道该函数入口点的绝对偏移量，这就不应阻止您跟踪此类函数。

示例：`-a "libjpeg.so!0x4793c"`

在此示例中，选项的值提供了模块的全名（即 `libjpeg.so`）和模块内函数入口点的十六进制偏移量（`0x4793c`）。

`frida-trace` 将为 `-a` 选项匹配的每个函数生成一个 JavaScript 处理程序文件。

## -P: 使用全局可访问的 JSON 对象初始化 frida-trace 会话

此选项允许将 JSON 对象分配给 `parameters` 全局变量。您的处理程序可以访问此全局变量，使您能够通过修改命令行上传递的 `-P` 的值来动态更改处理程序的行为。

传递的 JSON 对象可以随您所愿地复杂或广泛，只要它是有效的 JSON。

<div class="note">
  <h5>示例</h5>
  <p>
    在您的会话中，您正在跟踪许多函数。有时您希望所有处理程序打印出它们的进程 ID。使用 `-P` 选项，您可以启用处理程序来决定是否打印进程 ID。
  </p>
  <p>
    首先，确定通知处理程序是否应显示进程 ID 的 JSON 对象格式。让我们使用以下格式：

    <br>
    <br>
    <div style="font-family: monospace; text-indent: 40px">
      -P '{"displayPid": true}'
    </div>
    <br>

    请注意，此形式是您在 Linux 下可能使用的形式（即，您可以在命令行上同时使用单引号和双引号）。在 Windows 下，您只能使用双引号，因此您应该通过插入 <b>两个</b> 双引号来转义内部双引号，如下所示：

    <br>
    <br>
    <div style="font-family: monospace; text-indent: 40px">
      -P "{""displayPid"": true}"
    </div>
    <br>

    Frida-trace 将把您的 JSON 对象分配给全局 JavaScript 变量 "<i>parameters</i>"。现在，您的处理程序可以检查 parameters.displayPid 变量以决定是否打印进程 ID：

    <br>
    <br>

    <code>{
  onEnter(log, args, state) {
    log('memcpy() [msvcrt.dll]');
    if (parameters.displayPid) {
      log(`Process ID: ${Process.id}`);
    }
  },

  onLeave(log, retval, state) {
  }
}
</code>

    <br>
  </p>
</div>

## -S: 使用 JavaScript 代码初始化 frida-trace 会话

此选项通过执行您选择的一个或多个 JavaScript 代码文件来初始化您的 frida-trace 会话，这些文件可以声明全局可见的函数并将任意数据添加到全局 "state" 对象。当 "state" 对象传递给您的任何处理程序时，您可以立即访问您在会话初始化期间保存到其中的任何内容。

此强大功能的用途包括在会话开始之前初始化 frida-trace 运行环境，以及共享可以在不同处理程序和开发项目中调用的微调和调试过的 JavaScript 函数和数据。

有关如何使用此强大功能的详细说明，请参阅[会话初始化入门]({% link _docs/frida-trace/session-initialization-primer.md %})。

## -d, --decorate: 将模块名称添加到日志跟踪

`--decorate` 选项在 `frida-trace` 自动生成 JavaScript 处理程序脚本时相关。默认情况下，处理程序的 `onEnter` 函数如下所示：

<code>onEnter(log, args, state) {
  log('memcpy()');
},
</code>

缺点是，如果同一函数名存在于多个模块中，则很难区分函数跟踪。`--decorate` 函数指示 `frida-trace` 在默认的 `onEnter` 跟踪指令中插入模块名称：

<code>onEnter(log, args, state) {
  log('memcpy() [msvcrt.dll]');
},
</code>
