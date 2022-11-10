`gum-graft` is a tool for patching the binaries ahead of time.
It is especially useful when trying to use the Intercepotr api from the gadget on jail ios devices with `code_signing` enabled. 
You can download `gum-graft` from the [releases page](https://github.com/frida/frida/releases).

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