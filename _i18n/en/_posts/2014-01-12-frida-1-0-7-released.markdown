---
layout: news_item
title: 'Frida 1.0.7 Released'
date: 2014-01-12 23:00:00 +0100
author: oleavr
version: 1.0.7
categories: [release]
---

This release brings USB device support in the command-line tools, and
adds `frida-ps` for enumerating processes both locally and remotely.

For example to enumerate processes on your tethered iOS device:
{% highlight bash %}
$ frida-ps -U
{% endhighlight %}

The `-U` switch is also accepted by `frida-trace` and `frida-discover`.

Docs how to set this up on your iOS device will soon be added to the website.

However, that's not the most exciting part. Starting with this release,
Frida got its first contribution since the HN launch.
[Pete Morici](https://github.com/pmorici) dived in and contributed support
for specifying module-relative functions in `frida-trace`:

{% highlight bash %}
$ frida-trace -a 'kernel32.dll+0x1234'
{% endhighlight %}

Enjoy!
