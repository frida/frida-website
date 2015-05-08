---
layout: docs
title: frida-trace
prev_section: frida-ps
next_section: frida-discover
permalink: /docs/frida-trace/
---

frida-trace is a tool for dynamically tracing function calls.

{% highlight bash %}
# Trace recv* and send* APIs in Safari
$ frida-trace -i 'recv*' -i 'send*' Safari

# Trace ObjC method calls in Safari
$ frida-trace -m '-[NSView drawRect:]' Safari
{% endhighlight %}
