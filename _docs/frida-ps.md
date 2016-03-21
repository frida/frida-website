---
layout: docs
title: frida-ps
permalink: /docs/frida-ps/
---

This is a command-line tool for listing processes, which is very useful
when interacting with a remote system.

{% highlight bash %}
# Connect Frida to an iPad over USB and list running processes
$ frida-ps -U

# List running applications
$ frida-ps -Ua

# List installed applications
$ frida-ps -Uai
{% endhighlight %}
