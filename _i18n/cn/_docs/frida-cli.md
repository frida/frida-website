Frida CLI 是一个 REPL 接口，旨在模拟 IPython（或 Cycript）的许多不错的功能，它试图让您更接近您的代码，以便进行快速原型设计和轻松调试。

{% highlight bash %}
# 通过 USB 将 Frida 连接到 iPad 并开始调试 Safari
$ frida -U Safari

[USB::iPad 4::Safari]->
{% endhighlight %}

## 会话示例

{% highlight bash %}
# 将 Frida 连接到本地运行的 Calculator.app
$ frida Calculator

# 查看局部变量/上下文
[Local::ProcName::Calculator]-> <TAB>
Backtracer           Process
CpuContext           Proxy
Dalvik               Socket
DebugSymbol          Stalker
File                 Thread
Frida                WeakRef
Instruction          clearInterval
Interceptor          clearTimeout
Memory               console
MemoryAccessMonitor  gc
Module               ptr
NULL                 recv
NativeCallback       send
NativeFunction       setInterval
NativePointer        setTimeout
ObjC
# 查看通过 ObjC 接口暴露的内容
[Local::ProcName::Calculator]-> ObjC.<TAB>
Object            implement         selector
available         mainQueue         selectorAsString
classes           schedule
# 列出前 10 个类（有很多！）
[Local::...::Calculator]-> Object.keys(ObjC.classes).slice(0, 10)
[
    "NSDrawer",
    "GEOPDETAFilter",
    "NSDeserializer",
    "CBMutableCharacteristic",
    "NSOrthographyCheckingResult",
    "DDVariable",
    "GEOVoltaireLocationShiftProvider",
    "LSDocumentProxy",
    "NSPreferencesModule",
    "CIQRCodeGenerator"
]
{% endhighlight %}

## 加载脚本

{% highlight bash %}
# 将 Frida 连接到本地运行的 Calculator.app 并加载 calc.js
$ frida Calculator -l calc.js

# calc.js 中的代码现在已被加载并执行。任何更改都将自动重新加载
[Local::ProcName::Calculator]->

# 随时从文件手动重新加载它
[Local::ProcName::Calculator]-> %reload
[Local::ProcName::Calculator]->
{% endhighlight %}

## 启用 Node.js 兼容的调试器

{% highlight bash %}
# 将 Frida 连接到本地运行的 Calculator.app
# 并在启用调试器的情况下加载 calc.js
$ frida Calculator -l calc.js --debug

Debugger listening on port 5858
# 我们现在可以运行 node-inspector 并开始调试 calc.js
[Local::ProcName::Calculator]->
{% endhighlight %}
