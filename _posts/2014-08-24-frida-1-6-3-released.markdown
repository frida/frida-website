---
layout: news_item
title: 'Frida 1.6.3 Released'
date: 2014-08-24 23:00:00 +0100
author: oleavr
version: 1.6.3
categories: [release]
---

This latest release includes a bunch of enhancements and bug fixes.
Some of the highlights:

- The remainder of Frida's internals have been migrated from udis86 to
  Capstone, which means that our Stalker is now able to trace binaries with
  very recent x86 instructions. Part of this work also included battle-testing
  it on 32- and 64-bit binaries on Windows and Mac, and all known issues have
  now been resolved.

- `Memory.protect()` has been added to the JavaScript API, allowing you to
  easily change page protections. For example:

{% highlight js %}
Memory.protect(ptr("0x1234"), 4096, 'rw-');
{% endhighlight %}

- `Process.enumerateThreads()` omits Frida's own threads so you don't have to
  worry about them.

- Python 3 binaries are now built against Python 3.4.

So with this release out, let's talk about [CryptoShark](https://github.com/frida/cryptoshark):

<iframe width="560" height="315" src="//www.youtube.com/embed/hzDsxtcRavY?rel=0" frameborder="0" allowfullscreen></iframe>

Grab a pre-built Windows binary [here](http://build.frida.re/frida/windows/Win32-Release/bin/cryptoshark-0.1.1.exe),
or build it from source if you'd like to try it out on Mac or Linux.

Enjoy!
