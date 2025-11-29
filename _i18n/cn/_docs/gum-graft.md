`gum-graft` 工具用于提前修补二进制文件，以允许 Interceptor 在禁止运行时代码修改的环境中对它们进行插桩。目前，这仅指实施严格代码签名策略的 Apple 移动操作系统——即在没有附加调试器的情况下运行应用程序的未越狱系统。在这种情况下，覆盖 [Gadget][] `code_signing` 选项并将其设置为 `required`。

您可以从 [releases 页面][]下载 `gum-graft`。

{% highlight bash %}
Usage:
  gum-graft [OPTION?] BINARY - graft instrumentation into Mach-O binaries

Help Options:
  -h, --help                       Show help options

Application Options:
  -i, --instrument=0x1234          Include instrumentation for a specific code offset
  -s, --ingest-function-starts     Include instrumentation for offsets retrieved from LC_FUNCTION_STARTS
  -m, --ingest-imports             Include instrumentation for imports
  -z, --transform-lazy-binds       Transform lazy binds into regular binds (experimental)
{% endhighlight %}


[Gadget]: https://frida.re/docs/gadget/
[releases page]: https://github.com/frida/frida/releases
