The `gum-graft` tool is used for patching binaries ahead of time to allow
Interceptor to instrument them in environments where runtime code modifications
are prohibited. For now this only means Apple mobile OSes when strict
code-signing policies are at play -- i.e. on jailed systems when running an app
without a debugger having been attached. In such cases, override the [Gadget][]
`code_signing` option and set it to `required`.

You can download `gum-graft` from the [releases page][].

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